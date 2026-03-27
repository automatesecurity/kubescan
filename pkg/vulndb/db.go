package vulndb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"kubescan/pkg/policy"
	"kubescan/pkg/vuln"

	_ "modernc.org/sqlite"
)

const (
	SchemaName    = "kubescan-vulndb"
	SchemaVersion = "1.0.0"
)

type Info struct {
	Schema           string    `json:"schema"`
	SchemaVersion    string    `json:"schemaVersion"`
	AdvisoryCount    int       `json:"advisoryCount"`
	BuiltAt          time.Time `json:"builtAt"`
	BundleAPIVersion string    `json:"bundleApiVersion"`
	BundleKind       string    `json:"bundleKind"`
}

func Write(path string, bundle vuln.AdvisoryBundle) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove existing db: %w", err)
	}

	db, err := open(path)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := createSchema(db); err != nil {
		return err
	}

	now := time.Now().UTC()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := writeMetadata(tx, bundle, len(bundle.Advisories), now); err != nil {
		return err
	}
	for _, advisory := range bundle.Advisories {
		if err := insertAdvisory(tx, advisory); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func Load(path string) (vuln.AdvisoryBundle, error) {
	db, err := open(path)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	defer db.Close()

	info, err := readInfo(db)
	if err != nil {
		return vuln.AdvisoryBundle{}, err
	}
	if info.Schema != SchemaName {
		return vuln.AdvisoryBundle{}, fmt.Errorf("unsupported vulnerability db schema %q", info.Schema)
	}
	if info.SchemaVersion != SchemaVersion {
		return vuln.AdvisoryBundle{}, fmt.Errorf("unsupported vulnerability db schema version %q", info.SchemaVersion)
	}

	rows, err := db.Query(`
SELECT id, aliases_json, package_name, ecosystem, affected_versions_json, fixed_version, severity, summary
FROM advisories
ORDER BY id`)
	if err != nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("query advisories: %w", err)
	}
	defer rows.Close()

	bundle := vuln.AdvisoryBundle{
		APIVersion: info.BundleAPIVersion,
		Kind:       info.BundleKind,
	}
	for rows.Next() {
		var (
			advisory           vuln.Advisory
			aliasesJSON        string
			affectedVersionsJS string
			severity           string
		)
		if err := rows.Scan(
			&advisory.ID,
			&aliasesJSON,
			&advisory.PackageName,
			&advisory.Ecosystem,
			&affectedVersionsJS,
			&advisory.FixedVersion,
			&severity,
			&advisory.Summary,
		); err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("scan advisory: %w", err)
		}
		if err := json.Unmarshal([]byte(aliasesJSON), &advisory.Aliases); err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("decode aliases for %s: %w", advisory.ID, err)
		}
		if err := json.Unmarshal([]byte(affectedVersionsJS), &advisory.AffectedVersions); err != nil {
			return vuln.AdvisoryBundle{}, fmt.Errorf("decode affectedVersions for %s: %w", advisory.ID, err)
		}
		advisory.Severity = policy.Severity(severity)
		bundle.Advisories = append(bundle.Advisories, advisory)
	}
	if err := rows.Err(); err != nil {
		return vuln.AdvisoryBundle{}, fmt.Errorf("iterate advisories: %w", err)
	}
	return bundle, nil
}

func Inspect(path string) (Info, error) {
	db, err := open(path)
	if err != nil {
		return Info{}, err
	}
	defer db.Close()
	return readInfo(db)
}

func open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open vulnerability db: %w", err)
	}
	return db, nil
}

func createSchema(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE metadata (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE advisories (
	row_id INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL,
	aliases_json TEXT NOT NULL,
	package_name TEXT NOT NULL,
	ecosystem TEXT NOT NULL,
	affected_versions_json TEXT NOT NULL,
	fixed_version TEXT NOT NULL,
	severity TEXT NOT NULL,
	summary TEXT NOT NULL
);
CREATE INDEX advisories_id_idx ON advisories (id);
CREATE INDEX advisories_lookup_idx ON advisories (ecosystem, package_name);
`); err != nil {
		return fmt.Errorf("create vulnerability db schema: %w", err)
	}
	return nil
}

func writeMetadata(tx *sql.Tx, bundle vuln.AdvisoryBundle, advisoryCount int, builtAt time.Time) error {
	values := map[string]string{
		"schema":             SchemaName,
		"schema_version":     SchemaVersion,
		"bundle_api_version": bundle.APIVersion,
		"bundle_kind":        bundle.Kind,
		"advisory_count":     strconv.Itoa(advisoryCount),
		"built_at":           builtAt.Format(time.RFC3339Nano),
	}
	for key, value := range values {
		if _, err := tx.Exec(`INSERT INTO metadata(key, value) VALUES(?, ?)`, key, value); err != nil {
			return fmt.Errorf("insert metadata %s: %w", key, err)
		}
	}
	return nil
}

func insertAdvisory(tx *sql.Tx, advisory vuln.Advisory) error {
	aliasesJSON, err := json.Marshal(advisory.Aliases)
	if err != nil {
		return fmt.Errorf("marshal aliases for %s: %w", advisory.ID, err)
	}
	affectedVersionsJSON, err := json.Marshal(advisory.AffectedVersions)
	if err != nil {
		return fmt.Errorf("marshal affectedVersions for %s: %w", advisory.ID, err)
	}
	if _, err := tx.Exec(`
INSERT INTO advisories (
	id, aliases_json, package_name, ecosystem, affected_versions_json, fixed_version, severity, summary
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		advisory.ID,
		string(aliasesJSON),
		advisory.PackageName,
		advisory.Ecosystem,
		string(affectedVersionsJSON),
		advisory.FixedVersion,
		string(advisory.Severity),
		advisory.Summary,
	); err != nil {
		return fmt.Errorf("insert advisory %s: %w", advisory.ID, err)
	}
	return nil
}

func readInfo(db *sql.DB) (Info, error) {
	rows, err := db.Query(`SELECT key, value FROM metadata`)
	if err != nil {
		return Info{}, fmt.Errorf("query metadata: %w", err)
	}
	defer rows.Close()

	values := map[string]string{}
	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			return Info{}, fmt.Errorf("scan metadata: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return Info{}, fmt.Errorf("iterate metadata: %w", err)
	}

	count, err := strconv.Atoi(values["advisory_count"])
	if err != nil {
		return Info{}, fmt.Errorf("parse advisory count: %w", err)
	}
	builtAt, err := time.Parse(time.RFC3339Nano, values["built_at"])
	if err != nil {
		return Info{}, fmt.Errorf("parse built_at: %w", err)
	}

	return Info{
		Schema:           values["schema"],
		SchemaVersion:    values["schema_version"],
		AdvisoryCount:    count,
		BuiltAt:          builtAt,
		BundleAPIVersion: values["bundle_api_version"],
		BundleKind:       values["bundle_kind"],
	}, nil
}
