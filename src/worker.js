import { google } from 'googleapis';
import OpenAI from 'openai';
import { v4 as uuidv4 } from 'uuid';

// 학교 이메일 패턴
const ALLOWED_EMAIL_REGEX = /^25306\d{2}@areum\.hs\.kr$/;
// 화이트리스트 이메일(예: 관리자 등) - 추가 사용하려면 활용
const EMAIL_WHITELIST = [
  'laminggroub@gmail.com',
  'haveagooddayhappy@gmail.com',
  'overjjang99@gmail.com',
  '2530720@areum.hs.kr'
];

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const { pathname, searchParams } = url;
      const method = request.method.toUpperCase();

      // 정적 파일
      if (pathname === '/' || pathname === '/chat.html') {
        return env.ASSETS.fetch(request);
      }

      // OAuth 인증
      if (pathname === '/auth') return await this.handleAuth(request, env);
      if (pathname === '/auth/callback') return await this.handleAuthCallback(request, env);
      if (pathname === '/api/logout') return await this.handleLogout(request, env);

      // 프로필 조회
      if (pathname === '/api/profile' && method === 'GET') {
        return await this.handleProfile(request, env);
      }

      // 새 채팅 생성
      if (pathname === '/api/newChat' && method === 'POST') {
        return await this.handleNewChat(request, env);
      }

      // 채팅 목록 조회
      if (pathname === '/api/chatHistory' && method === 'GET') {
        return await this.getChatHistory(request, env);
      }

      // 특정 채팅 - 조회/삭제/이름변경
      if (pathname.startsWith('/api/chatHistory/')) {
        const chatId = pathname.replace('/api/chatHistory/', '');
        if (method === 'GET') {
          return await this.getChatMessages(request, env, chatId);
        } else if (method === 'DELETE') {
          return await this.deleteChat(request, env, chatId);
        } else if (method === 'PATCH') {
          return await this.renameChat(request, env, chatId);
        }
      }

      // 사용자 메시지 전송 (스트리밍 준비)
      if (pathname === '/api/chatStream' && method === 'POST') {
        return await this.handleChatStream(request, env);
      }

      // SSE 스트리밍
      if (pathname.startsWith('/api/stream/') && method === 'GET') {
        const chatId = pathname.replace('/api/stream/', '');
        return await this.handleSSEStream(request, env, chatId);
      }

      // 기타: 정적 파일
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },

  // ---------------------------------------------------------------------------
  // 1. OAuth 처리 (KV에 세션 저장) - 기존 로직과 동일
  // ---------------------------------------------------------------------------

  async handleAuth(request, env) {
    if (env.ENV === 'dev') {
      return await this.mockLogin(env);
    }
    const url = new URL(request.url);
    const state = uuidv4();
    await env.SESSION_KV.put(`state:${state}`, '1', { expirationTtl: 300 });

    const redirectUri = `${url.origin}/auth/callback`;
    const params = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state,
      prompt: 'select_account'
    });
    const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    return Response.redirect(redirectUrl, 302);
  },

  async handleAuthCallback(request, env) {
    if (env.ENV === 'dev') {
      return await this.mockLogin(env);
    }
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    const storedState = await env.SESSION_KV.get(`state:${state}`);
    if (!state || !storedState) {
      return new Response('잘못된 응답입니다. (처음부터 다시 로그인)', { status: 400 });
    }
    await env.SESSION_KV.delete(`state:${state}`);

    const redirectUri = `${url.origin}/auth/callback`;
    const oauth2Client = new google.auth.OAuth2(
      env.GOOGLE_CLIENT_ID,
      env.GOOGLE_CLIENT_SECRET,
      redirectUri
    );

    let tokens;
    try {
      const tokenResponse = await oauth2Client.getToken(code);
      tokens = tokenResponse.tokens;
    } catch (error) {
      console.error('Error fetching Google token:', error);
      return new Response('Failed to get token', { status: 400 });
    }
    oauth2Client.setCredentials(tokens);

    let userInfo;
    try {
      const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
      const userInfoResponse = await oauth2.userinfo.get();
      userInfo = userInfoResponse.data;
    } catch (error) {
      console.error('Error fetching user info:', error);
      return new Response('Failed to fetch user info', { status: 400 });
    }

    // 이메일 검증
    if (!userInfo || !userInfo.email) {
      return new Response('이메일이 없습니다.', { status: 400 });
    }
    if (!ALLOWED_EMAIL_REGEX.test(userInfo.email)) {
      if (!EMAIL_WHITELIST.includes(userInfo.email)) {
        return new Response('이용 불가한 이메일입니다 (3-6 학교 이메일이 아님)', { status: 403 });
      }
    }

    // 세션 생성
    const sessionId = uuidv4();
    const sessionData = {
      email: userInfo.email,
      picture: userInfo.picture || '',
      accessToken: tokens.access_token,
      expiresAt: Date.now() + (tokens.expires_in * 1000)
    };
    await env.SESSION_KV.put(`session:${sessionId}`, JSON.stringify(sessionData), {
      expirationTtl: tokens.expires_in,
    });

    const cookie = `sessionId=${sessionId}; HttpOnly; Path=/; Secure; SameSite=Lax;`;
    return new Response('', {
      status: 302,
      headers: {
        'Location': '/chat.html',
        'Set-Cookie': cookie,
      },
    });
  },

  async handleLogout(request, env) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionId = this.getCookie(cookieHeader, 'sessionId');
    if (sessionId) {
      await env.SESSION_KV.delete(`session:${sessionId}`);
    }
    return new Response('', {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': 'sessionId=; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=0',
      },
    });
  },

  // 개발 모드: Mock 로그인
  async mockLogin(env) {
    const sessionId = uuidv4();
    const email = '2530699@areum.hs.kr';
    const sessionData = {
      email,
      picture: '',
      accessToken: 'mock_access_token',
      expiresAt: Date.now() + 3600_000,
    };
    await env.SESSION_KV.put(`session:${sessionId}`, JSON.stringify(sessionData), {
      expirationTtl: 3600,
    });
    const cookie = `sessionId=${sessionId}; HttpOnly; Path=/; Secure; SameSite=Lax;`;
    return new Response('', {
      status: 302,
      headers: { 'Location': '/chat.html', 'Set-Cookie': cookie },
    });
  },

  // ---------------------------------------------------------------------------
  // 2. 프로필 조회 -> 세션은 KV, 프로필은 sessionData
  // ---------------------------------------------------------------------------
  async handleProfile(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    // sessionData.email, sessionData.picture
    return new Response(JSON.stringify({
      email: sessionData.email,
      profileImage: sessionData.picture
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // ---------------------------------------------------------------------------
  // 3. 채팅 목록 조회 (D1: account_data, chat_history)
  // ---------------------------------------------------------------------------
  async getChatHistory(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    // account_data에서 사용자의 chat_history_id 가져오기
    const accRow = await this.getOrCreateAccountData(env, email);
    const chatIdArr = JSON.parse(accRow.chat_history_id || '[]'); // ["chatId1","chatId2",...]

    const results = [];
    for (const chatId of chatIdArr) {
      // chat_history 테이블에서 chat_log 가져옴
      const row = await env.D1_DB.prepare(
        `SELECT chat_log FROM chat_history WHERE chat_id = ? LIMIT 1`
      ).bind(chatId).first();
      if (!row) continue;

      // chat_log는 JSON 문자열
      const messages = JSON.parse(row.chat_log || '[]');
      // "제목"을 구하는 간단 규칙: 첫 번째 user 메시지 or system "title" 
      const title = this.getChatTitle(messages);
      results.push({ chatId, title });
    }

    // 최신 내역이 위에 오도록 하려면 chatIdArr를 최근 것부터 저장하거나, 정렬 로직을 추가
    return new Response(JSON.stringify({ history: results }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // ---------------------------------------------------------------------------
  // 4. 특정 채팅 메시지 목록
  // ---------------------------------------------------------------------------
  async getChatMessages(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    // chat_history 검색
    const row = await env.D1_DB.prepare(
      `SELECT chat_log FROM chat_history WHERE chat_id = ? AND email = ? LIMIT 1`
    ).bind(chatId, email).first();
    if (!row) {
      return new Response(JSON.stringify({ messages: [] }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    const messages = JSON.parse(row.chat_log || '[]');
    return new Response(JSON.stringify({ messages }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // ---------------------------------------------------------------------------
  // 5. 새 채팅 생성
  // ---------------------------------------------------------------------------
  async handleNewChat(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    // account_data가 없으면 생성
    const accData = await this.getOrCreateAccountData(env, email);

    // 1) chat_id 생성
    const chatId = uuidv4();
    const createdAt = new Date().toISOString();

    // 2) chat_history row 추가 (chat_log는 빈 배열)
    await env.D1_DB.prepare(`
      INSERT INTO chat_history (chat_id, email, chat_log, created_at)
      VALUES (?, ?, ?, ?)
    `).bind(chatId, email, JSON.stringify([]), createdAt).run();

    // 3) account_data의 chat_history_id에 chatId 추가
    const chatIdArr = JSON.parse(accData.chat_history_id || '[]');
    chatIdArr.unshift(chatId); // 맨 앞에 삽입
    await env.D1_DB.prepare(`
      UPDATE account_data
      SET chat_history_id = ?
      WHERE email = ?
    `).bind(JSON.stringify(chatIdArr), email).run();

    // 결과 반환
    const response = { chatId, title: '새 채팅' };
    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // ---------------------------------------------------------------------------
  // 6. 채팅 삭제
  // ---------------------------------------------------------------------------
  async deleteChat(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    // chat_history에서 삭제
    await env.D1_DB.prepare(`
      DELETE FROM chat_history
      WHERE chat_id = ? AND email = ?
    `).bind(chatId, email).run();

    // account_data에서 해당 chatId 제거
    const accData = await this.getOrCreateAccountData(env, email);
    let chatIdArr = JSON.parse(accData.chat_history_id || '[]');
    chatIdArr = chatIdArr.filter(id => id !== chatId);
    await env.D1_DB.prepare(`
      UPDATE account_data
      SET chat_history_id = ?
      WHERE email = ?
    `).bind(JSON.stringify(chatIdArr), email).run();

    return new Response(JSON.stringify({ success: true }), { status: 200 });
  },

  // ---------------------------------------------------------------------------
  // 7. 채팅 이름 바꾸기
  // ---------------------------------------------------------------------------
  async renameChat(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    const { title } = await request.json();
    if (!title) {
      return new Response(JSON.stringify({ error: 'No title' }), { status: 400 });
    }

    // chat_history row 조회
    const row = await env.D1_DB.prepare(`
      SELECT chat_log FROM chat_history
      WHERE chat_id = ? AND email = ?
      LIMIT 1
    `).bind(chatId, email).first();
    if (!row) {
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }
    let messages = JSON.parse(row.chat_log || '[]');

    // 예시: 첫 번째 system 메시지를 "title: ???" 형태로 저장
    // 혹은 messages[0]이 user 메시지면 거기에 title로 표현하는 식으로 조정 가능
    if (messages.length === 0) {
      // 메시지가 하나도 없다면 system 메시지 생성
      messages = [{ role: 'system', content: `title: ${title}` }];
    } else {
      // system 메시지를 찾거나, 첫 메시지가 system이 아니면 삽입
      const systemMsg = messages.find(m => m.role === 'system');
      if (systemMsg) {
        systemMsg.content = `title: ${title}`;
      } else {
        messages.unshift({ role: 'system', content: `title: ${title}` });
      }
    }

    // 갱신
    await env.D1_DB.prepare(`
      UPDATE chat_history
      SET chat_log = ?
      WHERE chat_id = ? AND email = ?
    `).bind(JSON.stringify(messages), chatId, email).run();

    return new Response(JSON.stringify({ success: true }), { status: 200 });
  },

  // ---------------------------------------------------------------------------
  // 8. 채팅 스트리밍 준비 (user 메시지 등록)
  // ---------------------------------------------------------------------------
  async handleChatStream(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    const { chatId, message } = await request.json();
    if (!message) {
      return new Response(JSON.stringify({ error: 'No message' }), { status: 400 });
    }

    // 채팅이 없으면 새로 만들기
    let usedChatId = chatId || uuidv4();
    const row = await env.D1_DB.prepare(`
      SELECT chat_log FROM chat_history
      WHERE chat_id = ? AND email = ?
      LIMIT 1
    `).bind(usedChatId, email).first();

    if (!row) {
      // 채팅이 없으므로 새로 생성
      const createdAt = new Date().toISOString();
      await env.D1_DB.prepare(`
        INSERT INTO chat_history (chat_id, email, chat_log, created_at)
        VALUES (?, ?, ?, ?)
      `).bind(usedChatId, email, JSON.stringify([]), createdAt).run();
      // account_data에도 등록
      await this.addChatIdToAccount(env, email, usedChatId, true);
    }

    // user 메시지 push
    await this.pushMessageD1(env, email, usedChatId, { role: 'user', content: message });

    // chatId 반환
    return new Response(JSON.stringify({ chatId: usedChatId, status: 'ok' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // ---------------------------------------------------------------------------
  // 9. SSE 스트리밍 => OpenAI 응답
  // ---------------------------------------------------------------------------
  async handleSSEStream(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response('Unauthorized', { status: 401 });
    }
    const email = sessionData.email;

    // D1에서 chat_log 가져오기
    const row = await env.D1_DB.prepare(`
      SELECT chat_log FROM chat_history
      WHERE chat_id = ? AND email = ?
      LIMIT 1
    `).bind(chatId, email).first();
    if (!row) {
      return new Response('Chat not found', { status: 404 });
    }
    let allMessages = JSON.parse(row.chat_log || '[]');

    // OpenAI 모델에 보낼 messages
    // (system 역할도 포함 가능)
    const openaiMessages = allMessages.map(m => ({
      role: m.role,
      content: m.content
    }));

    // OpenAI 호출
    const openai = new OpenAI({ apiKey: env.OPENAI_API_KEY });
    let fullText = '';

    const stream = new ReadableStream({
      async start(controller) {
        try {
          const openaiRes = await openai.chat.completions.create({
            model: 'gpt-4o', // 필요 시 다른 모델
            messages: openaiMessages,
            stream: true
          });

          // SSE chunk 전송
          for await (const part of openaiRes) {
            const content = part.choices?.[0]?.delta?.content;
            if (content) {
              fullText += content;
              controller.enqueue(encodeSSE(content.replace(/\n/g, '\\n')));
            }
          }

          // assistant 메시지 DB에 저장
          await _this.pushMessageD1(env, email, chatId, {
            role: 'assistant', content: fullText
          });

          // 사용량(usage_count) 업데이트 (예: gpt-4o-mini +1)
          await _this.incrementUsageCount(env, email, 'gpt-4o-mini');

          // [DONE] 전송
          controller.enqueue(encodeSSE('[DONE]'));
          controller.close();
        } catch (err) {
          console.error('OpenAI SSE error:', err);
          controller.error(err);
        }
      }
    });

    // SSE 응답
    const headers = {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    };

    // Trick: "this" binding in async for-await
    const _this = this;
    return new Response(stream, { headers });
  },

  // ---------------------------------------------------------------------------
  // 10. 유틸 메서드들
  // ---------------------------------------------------------------------------

  // 세션 KV에서 가져오기
  async getSessionData(request, env) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionId = this.getCookie(cookieHeader, 'sessionId');
    if (!sessionId) return null;
    const sessionData = await env.SESSION_KV.get(`session:${sessionId}`);
    if (!sessionData) return null;
    return JSON.parse(sessionData);
  },
  getCookie(cookieHeader, name) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const c of cookies) {
      const [key, value] = c.split('=');
      if (key === name) return value;
    }
    return null;
  },

  // account_data row 없으면 생성
  async getOrCreateAccountData(env, email) {
    // 먼저 SELECT
    let row = await env.D1_DB.prepare(`
      SELECT email, usage_count, chat_history_id
      FROM account_data
      WHERE email = ?
      LIMIT 1
    `).bind(email).first();

    if (!row) {
      // 없으면 INSERT
      await env.D1_DB.prepare(`
        INSERT INTO account_data (email)
        VALUES (?)
      `).bind(email).run();

      // 다시 SELECT
      row = await env.D1_DB.prepare(`
        SELECT email, usage_count, chat_history_id
        FROM account_data
        WHERE email = ?
        LIMIT 1
      `).bind(email).first();
    }
    return row;
  },

  // 사용자의 chat_history_id 배열에 chatId 추가
  async addChatIdToAccount(env, email, chatId, unshift = false) {
    const accData = await this.getOrCreateAccountData(env, email);
    let arr = JSON.parse(accData.chat_history_id || '[]');
    if (arr.includes(chatId)) return; // 이미 있으면 무시
    if (unshift) arr.unshift(chatId);
    else arr.push(chatId);
    await env.D1_DB.prepare(`
      UPDATE account_data
      SET chat_history_id = ?
      WHERE email = ?
    `).bind(JSON.stringify(arr), email).run();
  },

  // DB에서 chat_log 읽고 append
  async pushMessageD1(env, email, chatId, { role, content }) {
    const row = await env.D1_DB.prepare(`
      SELECT chat_log FROM chat_history
      WHERE chat_id = ? AND email = ?
      LIMIT 1
    `).bind(chatId, email).first();
    if (!row) return; // 없으면 무시 or 에러
    let messages = JSON.parse(row.chat_log || '[]');
    messages.push({ role, content });
    await env.D1_DB.prepare(`
      UPDATE chat_history
      SET chat_log = ?
      WHERE chat_id = ? AND email = ?
    `).bind(JSON.stringify(messages), chatId, email).run();
  },

  // 사용량 업데이트 (usage_count: JSON)
  async incrementUsageCount(env, email, modelKey) {
    const accData = await this.getOrCreateAccountData(env, email);
    let usage = JSON.parse(accData.usage_count || '{"gpt-4o":0,"gpt-4o-mini":0}');
    if (!usage[modelKey]) usage[modelKey] = 0;
    usage[modelKey]++;
    await env.D1_DB.prepare(`
      UPDATE account_data
      SET usage_count = ?
      WHERE email = ?
    `).bind(JSON.stringify(usage), email).run();
  },

  // 메시지 목록에서 title 추출 (ex: 첫 system 메시지에서 `title: ???` 찾기)
  getChatTitle(messages) {
    if (!messages || messages.length === 0) return '새 채팅';
    // 1) system 메시지에서 title: ... 찾기
    const sysMsg = messages.find(m => m.role === 'system' && m.content.startsWith('title: '));
    if (sysMsg) {
      return sysMsg.content.replace('title: ', '').trim() || '새 채팅';
    }
    // 2) 없으면, 첫 user 메시지 일부를 썸네일로
    const userMsg = messages.find(m => m.role === 'user');
    if (userMsg) {
      return userMsg.content.slice(0, 20) || '새 채팅';
    }
    return '새 채팅';
  }
};

// SSE 포맷 변환
function encodeSSE(data) {
  return new TextEncoder().encode(`data: ${data}\n\n`);
}
