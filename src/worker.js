// worker.js (기존 코드 + 스트리밍, 추가 API)

import { google } from 'googleapis';
import OpenAI from 'openai';
import { v4 as uuidv4 } from 'uuid';

const ALLOWED_EMAIL_REGEX = /^25306\d{2}@areum\.hs\.kr$/;
const EMAIL_WHITELIST = [
    'laminggroub@gmail.com',
    ''
]

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      // 정적 파일
      if (path === '/' || path === '/chat.html') {
        return env.ASSETS.fetch(request);
      }

      // 인증 등 기존 로직
      if (path === '/auth') return await this.handleAuth(request, env);
      if (path === '/auth/callback') return await this.handleAuthCallback(request, env);
      if (path === '/api/logout') return await this.handleLogout(request, env);

      // 3) 프로필 조회
      if (path === '/api/profile' && method === 'GET') {
        return await this.handleProfile(request, env);
      }

      // 5) 새 채팅 생성
      if (path === '/api/newChat' && method === 'POST') {
        return await this.handleNewChat(request, env);
      }

      // 새 기능: 채팅 기록 조회
      if (path === '/api/chatHistory' && method === 'GET') {
        return await this.getChatHistory(request, env);
      }

      // 6) 특정 채팅 조작
      //    GET  /api/chatHistory/:chatId   → 메시지 목록 조회
      //    DELETE /api/chatHistory/:chatId → 채팅 삭제
      //    PATCH  /api/chatHistory/:chatId → 채팅 제목 변경
      if (path.startsWith('/api/chatHistory/')) {
        const chatId = path.replace('/api/chatHistory/', '');
        if (method === 'GET') {
          return await this.getChatMessages(request, env, chatId);
        } else if (method === 'DELETE') {
          return await this.deleteChat(request, env, chatId);
        } else if (method === 'PATCH') {
          return await this.renameChat(request, env, chatId);
        }
      }

      // 채팅 스트리밍 요청(POST)
      if (path === '/api/chatStream' && method === 'POST') {
        return await this.handleChatStream(request, env);
      }

      // SSE 스트리밍
      if (path.startsWith('/api/stream/') && method === 'GET') {
        const chatId = path.replace('/api/stream/', '');
        return await this.handleSSEStream(request, env, chatId);
      }

      // 채팅 API (기존 handleChat) - 필요시 유지
      // if (path === '/api/chat' && method === 'POST') { ... }

      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },

  // -------------------------
  // 예시: Google OAuth 관련 (생략 or 기존 로직)
  // -------------------------

  // 1. OAuth 시작
  async handleAuth(request, env) {
    // [개발 모드] Google OAuth를 사용하지 않고 즉시 Mock 로그인 처리
    if (env.ENV === 'dev') {
      return await this.mockLogin(env);
    }

    // [프로덕션 모드] 기존 Google OAuth 플로우
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

  // 2. OAuth 콜백
  async handleAuthCallback(request, env) {
    // [개발 모드] Google OAuth 콜백도 무시하고 Mock 로그인
    if (env.ENV === 'dev') {
      return await this.mockLogin(env);
    }

    // [프로덕션 모드] 기존 Google OAuth 콜백 처리
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    const storedState = await env.SESSION_KV.get(`state:${state}`);
    if (!state || !storedState) {
      return new Response('올바르지 않은 응답. <a href="/">메뉴로 돌아가기</a>', { status: 400, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
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

    if (!userInfo || !userInfo.email) {
      return new Response('이메일 찾지 못함', { status: 400 });
    }
    if (!ALLOWED_EMAIL_REGEX.test(userInfo.email)) {
      return new Response('이용 불가한 이메일입니다. 25306__@areum.hs.kr만 가능합니다.', { status: 403 });
    }

    const sessionId = uuidv4();
    const sessionData = {
      email: userInfo.email,
      picture: userInfo.picture,
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

  // [개발 모드] Mock 로그인 (임의 이메일로 세션 생성)
  async mockLogin(env) {
    const sessionId = uuidv4();
    const email = '2530699@areum.hs.kr'; // 원하는 임의 이메일
    const sessionData = {
      email,
      accessToken: 'mock_access_token',
      expiresAt: Date.now() + 3600_000, // 1시간 후 만료 (예시)
    };

    // 세션 저장
    await env.SESSION_KV.put(`session:${sessionId}`, JSON.stringify(sessionData), {
      expirationTtl: 3600, // 1시간
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

  // 3. 로그아웃
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

  // --------------------------
  // B. 프로필 조회 (GET /api/profile)
  // --------------------------
  async handleProfile(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    return new Response(JSON.stringify({ email: sessionData.email, profileImage: sessionData.picture }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },

  // -------------------------
  // 채팅 기록 목록 조회 (/api/chatHistory)
  // -------------------------
  async getChatHistory(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;
    // KV 키 스캔(간단 예시): chat:history:[email] => JSON [{chatId, title, ...}, ...]
    const histKey = `chat:history:${email}`;
    let historyRaw = await env.CHAT_KV.get(histKey);
    let history = historyRaw ? JSON.parse(historyRaw) : [];

    return new Response(JSON.stringify({ history }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // -------------------------
  // 특정 채팅 메시지 목록 (/api/chatHistory/:chatId)
  // -------------------------
  async getChatMessages(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;
    const chatKey = `chat:messages:${email}:${chatId}`;
    let chatRaw = await env.CHAT_KV.get(chatKey);
    let messages = chatRaw ? JSON.parse(chatRaw) : [];
    return new Response(JSON.stringify({ messages }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // POST /api/newChat : 새 채팅 생성
  async handleNewChat(request, env) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    const chatId = uuidv4();
    const defaultTitle = '새 채팅';
    // 1) 히스토리에 추가
    await this.addChatHistory(env, email, chatId, defaultTitle);
    // 2) 메시지 배열은 초기화(빈 목록)
    const chatKey = `chat:messages:${email}:${chatId}`;
    await env.CHAT_KV.put(chatKey, JSON.stringify([]));

    const response = { chatId, title: defaultTitle };
    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json' },
    });
  },

  // DELETE /api/chatHistory/:chatId : 채팅 삭제
  async deleteChat(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const email = sessionData.email;

    // 히스토리에서 해당 chatId 제거
    const histKey = `chat:history:${email}`;
    const raw = await env.CHAT_KV.get(histKey);
    let history = raw ? JSON.parse(raw) : [];

    history = history.filter(h => h.chatId !== chatId);
    await env.CHAT_KV.put(histKey, JSON.stringify(history));

    // 메시지 KV 삭제
    const chatKey = `chat:messages:${email}:${chatId}`;
    await env.CHAT_KV.delete(chatKey);

    return new Response(JSON.stringify({ success: true }), { status: 200 });
  },

  // PATCH /api/chatHistory/:chatId : 채팅 이름 바꾸기
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

    // 히스토리에서 해당 chatId 찾고 제목 변경
    const histKey = `chat:history:${email}`;
    const raw = await env.CHAT_KV.get(histKey);
    let history = raw ? JSON.parse(raw) : [];

    const idx = history.findIndex(h => h.chatId === chatId);
    if (idx === -1) {
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }
    history[idx].title = title;
    await env.CHAT_KV.put(histKey, JSON.stringify(history));

    return new Response(JSON.stringify({ success: true }), { status: 200 });
  },

  // -------------------------
  // 채팅 스트리밍 요청 (/api/chatStream) : POST
  // -------------------------
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

    // chatId 없으면 새로 생성
    let newChatId = chatId || uuidv4();
    // 1) 메시지 목록에 user 메시지 추가
    await this.pushMessage(env, email, newChatId, { role: 'user', content: message });

    // 2) 채팅 제목이 없으면 history에 추가(처음 생성 시)
    await this.ensureChatHistory(env, email, newChatId, message);

    // (여기선 OpenAI API 호출은 SSE에서 처리: handleSSEStream)
    // 지금은 단순히 chatId만 반환
    return new Response(JSON.stringify({ chatId: newChatId, status: 'ok' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // -------------------------
  // SSE 스트리밍 (/api/stream/:chatId)
  // -------------------------
  async handleSSEStream(request, env, chatId) {
    const sessionData = await this.getSessionData(request, env);
    if (!sessionData) {
      return new Response('Unauthorized', { status: 401 });
    }
    const email = sessionData.email;

    // OpenAI 스트리밍 호출
    // 1) OpenAI 라이브러리 생성
    const client = new OpenAI({ apiKey: env.OPENAI_API_KEY });

    // 2) 기존 메시지들 불러오기
    //    (원한다면, system이나 최근 메시지 요약해 컨텍스트로 보낼 수 있음)
    const messagesKey = `chat:messages:${email}:${chatId}`;
    let chatRaw = await env.CHAT_KV.get(messagesKey);
    let allMessages = chatRaw ? JSON.parse(chatRaw) : [];

    // OpenAI 모델에 보낼 messages
    // user/assistant/system 등을 포함
    // 여기서는 단순히 user/assistant 메시지를 정렬대로 보냄
    const openaiMessages = allMessages.map(m => ({
      role: m.role,
      content: m.content
    }));

    // 3) assistant 응답 스트리밍
    // SSE를 보내기 위한 ReadableStream 생성
    const stream = new ReadableStream({
      start: async(controller) => {
        try {
          let fullText = '';

          const openaiRes = await client.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: openaiMessages,
            stream: true
          });


          // openaiRes는 AsyncIterable 형태로 chunk를 가져올 수 있음
          for await (const part of openaiRes) {
            const content = part.choices?.[0]?.delta?.content;
            if (content) {
              fullText += content;
              // SSE 포맷으로 write
              controller.enqueue(encodeSSE(content));
            }
          }

          // Worker에서 assistant 메시지 저장
          await this.pushMessage(env, email, chatId, {
            role: 'assistant',
            content: fullText
          });

          // [DONE] 전송
          controller.enqueue(encodeSSE('[DONE]'));
          controller.close();


        } catch (error) {
          console.error('OpenAI SSE error:', error);
          controller.error(error);
        }
      }
    });

    // SSE 응답 헤더
    const headers = {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive'
    };
    return new Response(stream, { headers });
  },

  // -------------------------
  // 유틸 함수들
  // -------------------------

  // 세션 검사
  async getSessionData(request, env) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionId = this.getCookie(cookieHeader, 'sessionId');
    if (!sessionId) return null;
    const sessionDataJson = await env.SESSION_KV.get(`session:${sessionId}`);
    if (!sessionDataJson) return null;
    return JSON.parse(sessionDataJson);
  },

  // 쿠키 파싱
  getCookie(cookieHeader, name) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const c of cookies) {
      const [key, value] = c.split('=');
      if (key === name) return value;
    }
    return null;
  },

  async addChatHistory(env, email, chatId, title) {
    const histKey = `chat:history:${email}`;
    const raw = await env.CHAT_KV.get(histKey);
    let history = raw ? JSON.parse(raw) : [];
    // 중복 체크
    const exists = history.find(h => h.chatId === chatId);
    if (!exists) {
      history.unshift({ chatId, title });
      await env.CHAT_KV.put(histKey, JSON.stringify(history));
    }
  },

  // 메시지 목록에 push
  async pushMessage(env, email, chatId, { role, content }) {
    const messagesKey = `chat:messages:${email}:${chatId}`;
    let chatRaw = await env.CHAT_KV.get(messagesKey);
    let messages = chatRaw ? JSON.parse(chatRaw) : [];
    messages.push({ role, content });
    await env.CHAT_KV.put(messagesKey, JSON.stringify(messages));
  },

  // 히스토리 등록(처음 생성 시)
  async ensureChatHistory(env, email, chatId, firstMessage) {
    const histKey = `chat:history:${email}`;
    let histRaw = await env.CHAT_KV.get(histKey);
    let history = histRaw ? JSON.parse(histRaw) : [];
    // 이미 존재하는지 확인
    const exists = history.find(h => h.chatId === chatId);
    if (!exists) {
      // 첫 메시리를 간단히 잘라서 title 로
      const title = firstMessage.slice(0, 20) || 'New Chat';
      history.unshift({ chatId, title });
      await env.CHAT_KV.put(histKey, JSON.stringify(history));
    }
  }
};

// SSE 포맷으로 변환
function encodeSSE(data) {
  return new TextEncoder().encode(`data: ${data}\n\n`);
}
