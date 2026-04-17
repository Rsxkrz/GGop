import admin from 'firebase-admin';
import crypto from 'crypto';

// ==========================================
// 🔐 INIT FIREBASE
// ==========================================
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
        })
    });
}

const db = admin.firestore();
const ADMIN_EMAIL = "suporteggop@ggopsuport.com";

// ==========================================
// 🔑 GERAR KEY SEGURA
// ==========================================
function gerarKey() {
    return 'GG-' + crypto.randomBytes(6).toString('hex').toUpperCase();
}

// ==========================================
// ⏳ EXPIRAÇÃO
// ==========================================
function gerarExpiracao(dias = 30) {
    const data = new Date();
    data.setDate(data.getDate() + dias);
    return data;
}

// ==========================================
// 🚀 HANDLER
// ==========================================
export default async function handler(req, res) {
    const { action } = req.query;

    // ==========================================
    // 1. AUTH
    // ==========================================
    if (action === 'auth' && req.method === 'POST') {
        const { type, email, password } = req.body;

        const endpoint = type === 'login'
            ? `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`
            : `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${process.env.FIREBASE_API_KEY}`;

        const authRes = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, returnSecureToken: true })
        });

        const data = await authRes.json();

        if (data.error) {
            return res.status(400).json({ error: data.error.message.replace(/_/g, ' ') });
        }

        return res.status(200).json({
            token: data.idToken,
            email: data.email,
            uid: data.localId
        });
    }

    // ==========================================
    // 2. WEBHOOK MERCADO PAGO (SEGURO)
    // ==========================================
    if (action === 'webhook' && req.method === 'POST') {
        try {
            const paymentId = req.body?.data?.id;

            if (!paymentId) {
                return res.status(400).send("Pagamento inválido");
            }

            // 🔐 Consulta oficial no Mercado Pago
            const mpResponse = await fetch(
                `https://api.mercadopago.com/v1/payments/${paymentId}`,
                {
                    method: "GET",
                    headers: {
                        Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`
                    }
                }
            );

            const payment = await mpResponse.json();

            // ❌ Se não foi aprovado, ignora
            if (payment.status !== "approved") {
                return res.status(200).send("Pagamento não aprovado");
            }

            // 🔒 Evita duplicação
            const jaExiste = await db.collection("licencas")
                .where("payment_id", "==", payment.id)
                .limit(1)
                .get();

            if (!jaExiste.empty) {
                return res.status(200).send("Já processado");
            }

            // 📦 Dados reais
            const uid = payment.external_reference;
            const email = payment.payer?.email || null;
            const plano = payment.description || "GG Optimization - VIP";

            const key = gerarKey();

            await db.collection("licencas").doc(key).set({
                uid,
                email,
                plano,

                payment_id: payment.id,

                hwid: null,
                hwid_history:[],

                status: "active",

                created_at: admin.firestore.FieldValue.serverTimestamp(),
                expiry_date: gerarExpiracao(30)
            });

            return res.status(200).send("OK");

        } catch (error) {
            console.error("Erro webhook MP:", error);
            return res.status(500).send("Erro interno");
        }
    }

    // ==========================================
    // 🔒 AUTH MIDDLEWARE
    // ==========================================
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Não autenticado' });
    }

    const token = authHeader.split('Bearer ')[1];

    let user;
    try {
        user = await admin.auth().verifyIdToken(token);
    } catch {
        return res.status(401).json({ error: 'Token inválido' });
    }

    // ==========================================
    // 3. KEYS DO USUÁRIO
    // ==========================================
    if (action === 'keys' && req.method === 'GET') {
        const snap = await db.collection("licencas")
            .where("uid", "==", user.uid)
            .get();

        const lista =[];
        snap.forEach(doc => {
            lista.push({
                key: doc.id,
                ...doc.data()
            });
        });

        return res.json(lista);
    }

    // ==========================================
    // 4. ADMIN
    // ==========================================
    if (action === 'admin') {
        if (user.email.toLowerCase() !== ADMIN_EMAIL.toLowerCase()) {
            return res.status(403).json({ error: "Acesso negado" });
        }

        // LISTAR
        if (req.method === 'GET') {
            const snap = await db.collection("licencas").get();
            const lista =[];

            snap.forEach(doc => {
                lista.push({
                    key: doc.id,
                    ...doc.data()
                });
            });

            return res.json(lista);
        }

        // CRIAR
        if (req.method === 'POST') {
            const { uid, email, plano, dias } = req.body;

            const key = gerarKey();

            await db.collection("licencas").doc(key).set({
                uid,
                email,
                plano,

                hwid: null,
                hwid_history:[],

                status: "active",

                created_at: admin.firestore.FieldValue.serverTimestamp(),
                expiry_date: gerarExpiracao(dias || 30)
            });

            return res.json({ message: "Key criada", key });
        }

        // DELETAR
        if (req.method === 'DELETE') {
            const { key } = req.body;

            await db.collection("licencas").doc(key).delete();

            return res.json({ message: "Key deletada" });
        }

        // UPDATE (BAN / RESET HWID)
        if (req.method === 'PUT') {
            const { key, actionType } = req.body;

            const ref = db.collection("licencas").doc(key);
            const doc = await ref.get();

            if (!doc.exists) {
                return res.status(404).json({ error: "Key não encontrada" });
            }

            const data = doc.data();

            if (actionType === "reset_hwid") {
                await ref.update({
                    hwid: null,
                    hwid_history: [...(data.hwid_history || []), data.hwid]
                });
            }

            if (actionType === "ban") {
                await ref.update({ status: "banned" });
            }

            if (actionType === "unban") {
                await ref.update({ status: "active" });
            }

            return res.json({ message: "Atualizado com sucesso" });
        }
    }

    // ==========================================
    // 5. VALIDAR KEY
    // ==========================================
    if (action === 'validate' && req.method === 'POST') {
        const { key, hwid } = req.body;

        if (!key || !hwid) {
            return res.status(400).json({ error: "Dados inválidos" });
        }

        const ref = db.collection("licencas").doc(key);
        const doc = await ref.get();

        if (!doc.exists) {
            return res.status(404).json({ error: "Key inválida" });
        }

        const data = doc.data();

        if (data.status !== "active") {
            return res.status(403).json({ error: "Key desativada" });
        }

        if (data.expiry_date && data.expiry_date.toDate() < new Date()) {
            return res.status(403).json({ error: "Key expirada" });
        }

        if (!data.hwid) {
            await ref.update({ hwid });
            return res.json({ valid: true, plano: data.plano, firstBind: true });
        }

        if (data.hwid !== hwid) {
            return res.status(403).json({ error: "HWID inválido" });
        }

        return res.json({ valid: true, plano: data.plano });
    }

    // ==========================================
    // FALLBACK
    // ==========================================
    return res.status(404).json({ error: "Rota inválida" });
}