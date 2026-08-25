package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/katipwork/pratu/internal/courier"
)

const courierMaxAttempts = 5

// EnqueueMessage adds a message to the Courier outbox inside the caller's
// transaction, so it is sent only if the surrounding work commits.
func EnqueueMessage(ctx context.Context, tx pgx.Tx, tenantID, channel, recipient, template string, payload map[string]string) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO courier_messages (tenant_id, channel, recipient, template, payload)
		 VALUES ($1, $2, $3, $4, $5)`,
		tenantID, channel, recipient, template, raw)
	return err
}

// CourierDrain claims a batch of due messages and delivers them through the
// driver, recording success, retry backoff, or abandonment. It returns how
// many messages it attempted. The outbox is platform-level (no RLS), so
// this runs on the pool directly.
func CourierDrain(ctx context.Context, pool *pgxpool.Pool, driver courier.Driver) (int, error) {
	var attempted int
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, channel, recipient, template, payload, attempts
			   FROM courier_messages
			  WHERE status = 'pending' AND next_attempt_at <= now()
			  ORDER BY created_at
			  LIMIT 10
			    FOR UPDATE SKIP LOCKED`)
		if err != nil {
			return err
		}
		type claimed struct {
			msg      courier.Message
			attempts int
		}
		var batch []claimed
		for rows.Next() {
			var c claimed
			var payload []byte
			if err := rows.Scan(&c.msg.ID, &c.msg.TenantID, &c.msg.Channel, &c.msg.Recipient,
				&c.msg.Template, &payload, &c.attempts); err != nil {
				rows.Close()
				return err
			}
			if err := json.Unmarshal(payload, &c.msg.Payload); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, c := range batch {
			attempted++
			sendErr := driver.Send(ctx, c.msg)
			if sendErr == nil {
				_, err = tx.Exec(ctx,
					`UPDATE courier_messages SET status = 'sent', sent_at = now(), attempts = attempts + 1 WHERE id = $1`,
					c.msg.ID)
			} else if c.attempts+1 >= courierMaxAttempts {
				_, err = tx.Exec(ctx,
					`UPDATE courier_messages SET status = 'abandoned', attempts = attempts + 1, last_error = $2 WHERE id = $1`,
					c.msg.ID, sendErr.Error())
			} else {
				backoff := time.Duration(c.attempts+1) * 30 * time.Second
				_, err = tx.Exec(ctx,
					`UPDATE courier_messages SET attempts = attempts + 1, last_error = $2, next_attempt_at = $3 WHERE id = $1`,
					c.msg.ID, sendErr.Error(), time.Now().Add(backoff))
			}
			if err != nil {
				return fmt.Errorf("update courier message %s: %w", c.msg.ID, err)
			}
		}
		return nil
	})
	return attempted, err
}
