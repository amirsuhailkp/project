import type { Db } from '../db/types.js';

function boundModelCount(db: Db, keyId: number): number {
  const chat = db.prepare("SELECT COUNT(*) AS n FROM models WHERE platform = 'custom' AND key_id = ?").get(keyId) as { n: number };
  const embeddings = db.prepare("SELECT COUNT(*) AS n FROM embedding_models WHERE platform = 'custom' AND key_id = ?").get(keyId) as { n: number };
  const media = db.prepare("SELECT COUNT(*) AS n FROM media_models WHERE platform = 'custom' AND key_id = ?").get(keyId) as { n: number };
  return chat.n + embeddings.n + media.n;
}

export function deleteUnusedCustomEndpointKey(db: Db, keyId: number | null | undefined) {
  if (keyId == null) return;
  if (boundModelCount(db, keyId) > 0) return;

  const row = db.prepare("SELECT base_url FROM api_keys WHERE id = ? AND platform = 'custom'")
    .get(keyId) as { base_url: string | null } | undefined;
  db.prepare("DELETE FROM api_keys WHERE id = ? AND platform = 'custom'").run(keyId);
  if (!row?.base_url) return;

  // An endpoint can hold several credentials (#619). Once nothing is registered
  // against it any more, its other keys are dead weight too — but a sibling that
  // still carries models of its own stays.
  const siblings = db.prepare("SELECT id FROM api_keys WHERE platform = 'custom' AND base_url = ?")
    .all(row.base_url) as { id: number }[];
  for (const sibling of siblings) {
    if (boundModelCount(db, sibling.id) === 0) {
      db.prepare('DELETE FROM api_keys WHERE id = ?').run(sibling.id);
    }
  }
}
