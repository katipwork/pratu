package storage

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EncryptAtRest upgrades legacy plaintext secrets to the configured
// cipher: tenant signing keys and second-factor credential configs. Runs
// at startup when encryption is enabled; tenant by tenant because the
// rows live under RLS.
func EncryptAtRest(ctx context.Context, pool *pgxpool.Pool) (keys, creds int, err error) {
	if cipher == nil {
		return 0, 0, nil
	}
	rows, err := pool.Query(ctx, `SELECT id::text FROM tenants`)
	if err != nil {
		return 0, 0, err
	}
	var tenantIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, 0, err
		}
		tenantIDs = append(tenantIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	for _, tenantID := range tenantIDs {
		err := InTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
			k, err := sweepTenantKeys(ctx, tx)
			if err != nil {
				return err
			}
			keys += k
			c, err := sweepCredentials(ctx, tx)
			if err != nil {
				return err
			}
			creds += c
			return nil
		})
		if err != nil {
			return keys, creds, err
		}
	}
	return keys, creds, nil
}

func sweepTenantKeys(ctx context.Context, tx pgx.Tx) (int, error) {
	rows, err := tx.Query(ctx,
		`SELECT id::text, private_pem FROM tenant_keys WHERE private_pem NOT LIKE 'enc:%'`)
	if err != nil {
		return 0, err
	}
	type row struct{ id, pem string }
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.pem); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range pending {
		sealed, err := cipher.Encrypt(r.pem)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_keys SET private_pem = $2 WHERE id = $1`, r.id, sealed); err != nil {
			return 0, err
		}
	}
	return len(pending), nil
}

func sweepCredentials(ctx context.Context, tx pgx.Tx) (int, error) {
	rows, err := tx.Query(ctx,
		`SELECT id::text, config FROM identity_credentials
		  WHERE kind IN ('totp', 'sms') AND jsonb_typeof(config) = 'object'`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id     string
		config []byte
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.config); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range pending {
		sealed, err := cipher.Encrypt(string(r.config))
		if err != nil {
			return 0, err
		}
		quoted, err := json.Marshal(sealed)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_credentials SET config = $2 WHERE id = $1`, r.id, quoted); err != nil {
			return 0, err
		}
	}
	return len(pending), nil
}
