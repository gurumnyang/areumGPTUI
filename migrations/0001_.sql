-- Migration number: 0001 	 2025-03-17T02:22:09.900Z
-- 채팅 기록 테이블
CREATE TABLE IF NOT EXISTS chat_history (
  chat_id TEXT PRIMARY KEY,   -- 채팅 고유 ID
  email TEXT NOT NULL,        -- 사용자 이메일
  chat_log TEXT NOT NULL,     -- JSON 직렬화된 채팅 메시지
  created_at TEXT DEFAULT (datetime('now')) -- 채팅 생성 시간
);

-- 사용자 데이터 테이블
CREATE TABLE IF NOT EXISTS account_data (
  email TEXT PRIMARY KEY,     -- 유저 이메일 (고유)
  usage_count TEXT DEFAULT '{"gpt-4o":0,"gpt-4o-mini":0}',  -- 모델별 사용량(JSON)
  chat_history_id TEXT DEFAULT '[]'  -- 사용자가 보유한 chat_id 목록 (JSON 배열)
);

-- 기본 인덱스 추가 (쿼리 최적화)
CREATE INDEX IF NOT EXISTS idx_chat_email ON chat_history(email);
CREATE INDEX IF NOT EXISTS idx_account_email ON account_data(email);
