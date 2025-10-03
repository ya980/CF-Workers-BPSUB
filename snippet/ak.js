const FIXED_UUID = '';// stallTCP.js from https://t.me/Enkelte_notif/784
import { connect } from "cloudflare:sockets";
let 反代IP = '';
let 启用SOCKS5反代 = null;
let 启用SOCKS5全局反代 = false;
let 我的SOCKS5账号 = '';
//////////////////////////////////////////////////////////////////////////stall参数////////////////////////////////////////////////////////////////////////
const KEEPALIVE_INTERVAL = 20000; // 20秒心跳，更频繁
const STALL_TIMEOUT = 8000; // 8秒无数据认为stall
const MAX_STALL_COUNT = 8; // 允许8次stall再重连
const MAX_RECONNECT_COUNT = 15; // 最大重连次数
//////////////////////////////////////////////////////////////////////////主要架构////////////////////////////////////////////////////////////////////////
export default {
    async fetch(request) {
        const url = new URL(request.url);
        我的SOCKS5账号 = url.searchParams.get('socks5') || url.searchParams.get('http');
        启用SOCKS5全局反代 = url.searchParams.has('globalproxy');
        if (url.pathname.toLowerCase().includes('/socks5=') || (url.pathname.includes('/s5=')) || (url.pathname.includes('/gs5='))) {
            我的SOCKS5账号 = url.pathname.split('5=')[1];
            启用SOCKS5反代 = 'socks5';
            启用SOCKS5全局反代 = url.pathname.includes('/gs5=') ? true : 启用SOCKS5全局反代;
        } else if (url.pathname.toLowerCase().includes('/http=')) {
            我的SOCKS5账号 = url.pathname.split('/http=')[1];
            启用SOCKS5反代 = 'http';
        } else if (url.pathname.toLowerCase().includes('/socks://') || url.pathname.toLowerCase().includes('/socks5://') || url.pathname.toLowerCase().includes('/http://')) {
            启用SOCKS5反代 = (url.pathname.includes('/http://')) ? 'http' : 'socks5';
            我的SOCKS5账号 = url.pathname.split('://')[1].split('#')[0];
            if (我的SOCKS5账号.includes('@')) {
                const lastAtIndex = 我的SOCKS5账号.lastIndexOf('@');
                let userPassword = 我的SOCKS5账号.substring(0, lastAtIndex).replaceAll('%3D', '=');
                const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                我的SOCKS5账号 = `${userPassword}@${我的SOCKS5账号.substring(lastAtIndex + 1)}`;
            }
            启用SOCKS5全局反代 = true;//开启全局SOCKS5
        }

        if (我的SOCKS5账号) {
            try {
                获取SOCKS5账号(我的SOCKS5账号);
                启用SOCKS5反代 = url.searchParams.get('http') ? 'http' : 启用SOCKS5反代;
            } catch (err) {
                启用SOCKS5反代 = null;
            }
        } else {
            启用SOCKS5反代 = null;
        }

        if (url.searchParams.has('proxyip')) {
            反代IP = url.searchParams.get('proxyip');
            启用SOCKS5反代 = null;
        } else if (url.pathname.toLowerCase().includes('/proxyip=')) {
            反代IP = url.pathname.toLowerCase().split('/proxyip=')[1];
            启用SOCKS5反代 = null;
        } else if (url.pathname.toLowerCase().includes('/proxyip.')) {
            反代IP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
            启用SOCKS5反代 = null;
        } else if (url.pathname.toLowerCase().includes('/pyip=')) {
            反代IP = url.pathname.toLowerCase().split('/pyip=')[1];
            启用SOCKS5反代 = null;
        } else if (url.pathname.toLowerCase().includes('/ip=')) {
            反代IP = url.pathname.toLowerCase().split('/ip=')[1];
            启用SOCKS5反代 = null;
        }

        if (request.headers.get('Upgrade') !== 'websocket') {
            return new Response('Hello World!', { status: 200 });
        }

        const pair = new WebSocketPair();
        const [client, server] = [pair[0], pair[1]];
        server.accept();
        handleConnection(server);
        return new Response(null, { status: 101, webSocket: client });
    }
};
function buildUUID(arr, start) {
    const hex = Array.from(arr.slice(start, start + 16)).map(n => n.toString(16).padStart(2, '0')).join('');
    return hex.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}
function handleConnection(ws) {
    let socket, writer, reader;
    let isFirstMsg = true;
    let writeQueue = Promise.resolve();
    let readQueue = Promise.resolve();
    let lastActivity = Date.now();
    let lastDataReceived = Date.now();
    let keepaliveTimer = null;
    let healthCheckTimer = null;
    let connectionInfo = null;
    let isReconnecting = false;
    let bytesReceived = 0;
    let reconnectCount = 0;
    let stallCount = 0;
    let versionByte = 0;
    ws.addEventListener('message', async (evt) => {
        try {
            if (isFirstMsg) {
                isFirstMsg = false;
                const result = await processHandshake(evt.data);
                socket = result.socket;
                writer = result.writer;
                reader = result.reader;
                connectionInfo = result.info;
                versionByte = result.version;
                ws.send(new Uint8Array([versionByte, 0]));
                startReading();
                startKeepalive();
                startHealthCheck();
            } else {
                lastActivity = Date.now();
                writeQueue = writeQueue.then(async () => {
                    try {
                        await writer.write(evt.data);
                    } catch (err) {
                        console.error('Write error:', err);
                        throw err;
                    }
                }).catch(() => {
                    if (!isReconnecting) {
                        setTimeout(() => attemptReconnect(), 100);
                    }
                });
            }
        } catch (err) {
            console.error('Connection error:', err);
            cleanup();
            ws.close(1006, 'Connection abnormal');
        }
    });
    async function processHandshake(data) {
        const bytes = new Uint8Array(data);
        const versionByte = bytes[0];
        const authKey = buildUUID(bytes, 1);
        if (FIXED_UUID && authKey !== FIXED_UUID) {
            throw new Error('Auth failed');
        }
        const addrInfo = extractAddress(bytes);
        if (addrInfo.host.includes(atob('c3BlZWQuY2xvdWRmbGFyZS5jb20='))) throw new Error('Access');
        let sock;
        if (启用SOCKS5反代 == 'socks5' && 启用SOCKS5全局反代) {
            sock = await socks5Connect(addrInfo.host, addrInfo.port);
        } else if (启用SOCKS5反代 == 'http' && 启用SOCKS5全局反代) {
            sock = await httpConnect(addrInfo.host, addrInfo.port);
        } else {
            try {
                sock = connect({ hostname: addrInfo.host, port: addrInfo.port });
                await sock.opened;
            } catch {
                if (启用SOCKS5反代 == 'socks5') {
                    sock = await socks5Connect(addrInfo.host, addrInfo.port);
                } else if (启用SOCKS5反代 == 'http') {
                    sock = await httpConnect(addrInfo.host, addrInfo.port);
                } else {
                    let [反代IP地址, 反代IP端口] = 解析地址端口(反代IP);
                    sock = connect({ hostname: 反代IP地址, port: 反代IP端口 });
                }
            }
        }
        await sock.opened;
        const w = sock.writable.getWriter();
        const r = sock.readable.getReader();
        if (addrInfo.payload.length > 0) {
            await w.write(addrInfo.payload);
        }
        return {
            socket: sock,
            writer: w,
            reader: r,
            info: { host: addrInfo.host, port: addrInfo.port },
            version: versionByte
        };
    }
    async function startReading() {
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (value && value.length > 0) {
                    bytesReceived += value.length;
                    lastDataReceived = Date.now();
                    lastActivity = Date.now();
                    stallCount = 0;
                    reconnectCount = 0;
                    readQueue = readQueue.then(() => {
                        if (ws.readyState === 1) {
                            return ws.send(value);
                        }
                    }).catch(() => { });
                }
                if (done) {
                    console.log('Stream ended gracefully');
                    await attemptReconnect();
                    break;
                }
            }
        } catch (err) {
            console.error('Read error:', err);
            if (!isReconnecting) {
                await attemptReconnect();
            }
        }
    }
    async function attemptReconnect() {
        if (isReconnecting || !connectionInfo || ws.readyState !== 1) {
            return;
        }
        isReconnecting = true;
        reconnectCount++;
        console.log(`Reconnecting (attempt ${reconnectCount})...`);
        try {
            try {
                writer?.releaseLock();
                reader?.releaseLock();
            } catch (e) { }
            try {
                socket?.close();
            } catch (e) { }
            await new Promise(resolve => setTimeout(resolve, 300));
            const sock = connect({
                hostname: connectionInfo.host,
                port: connectionInfo.port
            });
            await sock.opened;
            socket = sock;
            writer = sock.writable.getWriter();
            reader = sock.readable.getReader();
            lastActivity = Date.now();
            lastDataReceived = Date.now();
            stallCount = 0;
            console.log('Reconnected successfully');
            isReconnecting = false;
            startReading();
        } catch (err) {
            console.error('Reconnect failed:', err);
            isReconnecting = false;
            if (ws.readyState === 1 && reconnectCount < MAX_RECONNECT_COUNT) {
                setTimeout(() => attemptReconnect(), 1000);
            } else {
                cleanup();
                ws.close(1011, 'Reconnection failed');
            }
        }
    }
    function startKeepalive() {
        keepaliveTimer = setInterval(async () => {
            const idle = Date.now() - lastActivity;
            if (idle > KEEPALIVE_INTERVAL && !isReconnecting) {
                try {
                    await writer.write(new Uint8Array(0));
                    lastActivity = Date.now();
                } catch (e) {
                    console.error('Keepalive failed:', e);
                }
            }
        }, KEEPALIVE_INTERVAL / 2);
    }
    function startHealthCheck() {
        healthCheckTimer = setInterval(() => {
            const timeSinceData = Date.now() - lastDataReceived;
            if (bytesReceived > 0 && timeSinceData > STALL_TIMEOUT && !isReconnecting) {
                stallCount++;
                console.log(`Stall detected (${stallCount}/${MAX_STALL_COUNT}), ${timeSinceData}ms since last data`);
                if (stallCount >= MAX_STALL_COUNT) {
                    console.log('Multiple stalls detected, reconnecting...');
                    attemptReconnect();
                }
            }
        }, STALL_TIMEOUT / 2);
    }
    function cleanup() {
        if (keepaliveTimer) {
            clearInterval(keepaliveTimer);
            keepaliveTimer = null;
        }
        if (healthCheckTimer) {
            clearInterval(healthCheckTimer);
            healthCheckTimer = null;
        }
        try {
            writer?.releaseLock();
            reader?.releaseLock();
        } catch (e) { }
        try {
            socket?.close();
        } catch (e) { }
    }
    ws.addEventListener('close', cleanup);
    ws.addEventListener('error', cleanup);
}
function extractAddress(bytes) {
    const offset1 = 18 + bytes[17] + 1;
    const port = (bytes[offset1] << 8) | bytes[offset1 + 1];
    const addrType = bytes[offset1 + 2];
    let offset2 = offset1 + 3;
    let length, host;
    switch (addrType) {
        case 1:
            length = 4;
            host = bytes.slice(offset2, offset2 + length).join('.');
            break;
        case 2:
            length = bytes[offset2];
            offset2++;
            host = new TextDecoder().decode(bytes.slice(offset2, offset2 + length));
            break;
        case 3:
            length = 16;
            const segments = [];
            for (let i = 0; i < 8; i++) {
                const seg = (bytes[offset2 + i * 2] << 8) | bytes[offset2 + i * 2 + 1];
                segments.push(seg.toString(16));
            }
            host = `[${segments.join(':')}]`;
            break;
        default:
            throw new Error('Invalid address type.');
    }
    const payload = bytes.slice(offset2 + length);
    return { host, port, payload };
}

async function 获取SOCKS5账号(address) {
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }
    const latters = latter.split(":");
    if (latters.length > 2 && latter.includes("]:")) {
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]";
    } else if (latters.length === 2) {
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }
    return { username, password, hostname, port };
}
function 解析地址端口(反代IP) {
    const proxyIP = 反代IP.toLowerCase();
    let 地址 = proxyIP, 端口 = 443;
    if (!proxyIP || proxyIP == '') {
        地址 = 'proxyip.fxxk.dedyn.io';
    } else if (proxyIP.includes(']:')) {
        端口 = proxyIP.split(']:')[1] || 端口;
        地址 = proxyIP.split(']:')[0] + "]" || 地址;
    } else if (proxyIP.split(':').length === 2) {
        端口 = proxyIP.split(':')[1] || 端口;
        地址 = proxyIP.split(':')[0] || 地址;
    }
    if (proxyIP.includes('.tp')) 端口 = proxyIP.split('.tp')[1].split('.')[0] || 端口;
    return [地址, 端口];
}
async function httpConnect(addressRemote, portRemote) {
    const { username, password, hostname, port } = await 获取SOCKS5账号(我的SOCKS5账号);
    const sock = await connect({ hostname, port });
    const authHeader = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
    const connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n` +
        `Host: ${addressRemote}:${portRemote}\r\n` +
        authHeader +
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n` +
        `Proxy-Connection: Keep-Alive\r\n` +
        `Connection: Keep-Alive\r\n\r\n`;
    const writer = sock.writable.getWriter();
    try {
        await writer.write(new TextEncoder().encode(connectRequest));
    } catch (err) {
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    } finally {
        writer.releaseLock();
    }
    const reader = sock.readable.getReader();
    let responseBuffer = new Uint8Array(0);
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) throw new Error('HTTP代理连接中断');
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            const respText = new TextDecoder().decode(responseBuffer);
            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                if (!headers.startsWith('HTTP/1.1 200') && !headers.startsWith('HTTP/1.0 200')) {
                    throw new Error(`HTTP代理连接失败: ${headers.split('\r\n')[0]}`);
                }
                if (headersEndPos < responseBuffer.length) {
                    const remainingData = responseBuffer.slice(headersEndPos);
                    const { readable, writable } = new TransformStream();
                    new ReadableStream({
                        start(controller) {
                            controller.enqueue(remainingData);
                        }
                    }).pipeTo(writable).catch(() => { });
                    // @ts-ignore
                    sock.readable = readable;
                }
                break;
            }
        }
    } catch (err) {
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    } finally {
        reader.releaseLock();
    }
    return sock;
}

async function socks5Connect(targetHost, targetPort) {
    const parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号);
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = connect({
        hostname: hostname,
        port: port
    });
    await sock.opened;
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();
    await w.write(new Uint8Array([5, 2, 0, 2]));
    const auth = (await r.read()).value;
    if (auth[1] === 2 && username) {
        const user = new TextEncoder().encode(username);
        const pass = new TextEncoder().encode(password);
        await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
        await r.read();
    }
    const domain = new TextEncoder().encode(targetHost);
    await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain,
        targetPort >> 8, targetPort & 0xff
    ]));
    await r.read();
    w.releaseLock();
    r.releaseLock();
    return sock;
}