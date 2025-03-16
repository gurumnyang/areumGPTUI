// src/worker.js

import { google } from 'googleapis';
import OpenAI from 'openai';
import { v4 as uuidv4 } from 'uuid';

// 특정 이메일 패턴: 24306nn@areum.hs.kr (nn: 두자리 숫자)
const ALLOWED_EMAIL_REGEX = /^24306\d{2}@areum\.hs\.kr$/;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      // 라우팅 처리
      if (url.pathname === '/') {
        return env.ASSETS.fetch(request);
      }
      if (url.pathname === '/chat.html') {
        return env.ASSETS.fetch(request);
      }
      if (url.pathname === '/auth') {
        return await this.handleAuth(request, env);
      }
      if (url.pathname === '/auth/callback') {
        return await this.handleAuthCallback(request, env);
      }
      if (url.pathname === '/api/logout') {
        return await this.handleLogout(request, env);
      }
      if (url.pathname === '/api/chat') {
        if (request.method === 'POST') {
          return await this.handleChat(request, env);
        }
        return new Response('Method Not Allowed', { status: 405 });
      }
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error(err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },

  // 1. OAuth 시작
  async handleAuth(request, env) {
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

  // 2. OAuth 콜백 (googleapis 라이브러리 사용)
  async handleAuthCallback(request, env) {
    const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    const storedState = await env.SESSION_KV.get(`state:${state}`);
    if (!state || !storedState) {
      return new Response('Invalid state', { status: 400 });
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
      return new Response('No email found', { status: 400 });
    }
    if (!ALLOWED_EMAIL_REGEX.test(userInfo.email)) {
      return new Response('Access Denied', { status: 403 });
    }

    const sessionId = uuidv4();
    const sessionData = {
      email: userInfo.email,
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

  // 4. 채팅 API (OpenAI 라이브러리 최신 사용법)
  async handleChat(request, env) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionId = this.getCookie(cookieHeader, 'sessionId');
    if (!sessionId) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }
    const sessionDataJson = await env.SESSION_KV.get(`session:${sessionId}`);
    if (!sessionDataJson) {
      return new Response(JSON.stringify({ error: 'Session expired or invalid' }), { status: 401 });
    }
    const sessionData = JSON.parse(sessionDataJson);

    const body = await request.json();
    const userMessage = body.message || '';
    if (!userMessage) {
      return new Response(JSON.stringify({ error: 'No message provided' }), { status: 400 });
    }

    let assistantMessage = '';
    try {
      // OpenAI 라이브러리 사용: 최신 문서에 따른 chat completions 호출 방식
      const client = new OpenAI({ apiKey: env.OPENAI_API_KEY });
      const completion = await client.chat.completions.create({
        model: 'gpt-3.5-turbo', // 또는 'gpt-4o' 등 원하는 모델
        messages: [
          { role: 'system', content: 'You are a helpful tutor for students.' },
          { role: 'user', content: userMessage }
        ]
      });
      assistantMessage = completion.choices[0].message.content;
    } catch (error) {
      console.error('Error with OpenAI API:', error);
      return new Response(JSON.stringify({ error: 'Failed to get response from OpenAI' }), { status: 500 });
    }

    // 대화 내용 저장 (KV DB)
    const chatKey = `chat:${sessionData.email}:${Date.now()}`;
    await env.CHAT_KV.put(chatKey, JSON.stringify({
      user: userMessage,
      assistant: assistantMessage,
      timestamp: new Date().toISOString()
    }));

    // 사용량 집계 (간단 예시)
    const usageKey = `usage:${sessionData.email}`;
    const usage = await env.CHAT_KV.get(usageKey);
    let usageCount = usage ? parseInt(usage, 10) : 0;
    usageCount++;
    await env.CHAT_KV.put(usageKey, usageCount.toString());

    return new Response(JSON.stringify({ assistant: assistantMessage }), {
      headers: { 'Content-Type': 'application/json' }
    });
  },

  // 쿠키 파싱 함수
  getCookie(cookieHeader, name) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    for (const c of cookies) {
      const [key, value] = c.split('=');
      if (key === name) {
        return value;
      }
    }
    return null;
  }
};
