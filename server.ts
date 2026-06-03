import express, { Request, Response } from 'express';
import path from 'path';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Body parser for form submissions and JSON inputs
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // PayU Test Configuration
  const PAYU_MERCHANT_KEY = "ndYBUT";
  const PAYU_SALT = process.env.PAYU_SALT || "e5i6Yg2M"; // Fallback test salt

  // API Route: Secure Hash Generation for PayU
  app.post("/api/payments/payu-hash", (req: Request, res: Response) => {
    try {
      const { txnid, amount, productinfo, firstname, email, udf1, udf2, udf3, udf4, udf5 } = req.body;

      if (!txnid || !amount || !productinfo || !firstname || !email) {
        return res.status(400).json({ error: "Missing required hash parameters" });
      }

      // Hash formula: sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||SALT)
      const u1 = udf1 || "";
      const u2 = udf2 || "";
      const u3 = udf3 || "";
      const u4 = udf4 || "";
      const u5 = udf5 || "";

      const hashString = `${PAYU_MERCHANT_KEY}|${txnid}|${amount}|${productinfo}|${firstname}|${email}|${u1}|${u2}|${u3}|${u4}|${u5}||||||${PAYU_SALT}`;
      const hash = crypto.createHash('sha512').update(hashString).digest('hex');

      return res.json({ hash });
    } catch (error: any) {
      console.error("Error generating PayU hash:", error);
      return res.status(500).json({ error: error.message });
    }
  });

  // PayU Course Purchase Direct Webhook / Redirection endpoint
  app.post("/api/payments/success", (req: Request, res: Response) => {
    // PayU POST back to this URL upon success
    const { txnid, amount, productinfo, firstname, email, udf1, status } = req.body;
    console.log("PayU success callback received:", req.body);
    
    // Redirect back to user.html with success parameters
    const redirectUrl = `/user.html?paymentStatus=success&txnid=${txnid || ''}&amount=${amount || ''}&courseId=${productinfo || ''}&uid=${udf1 || ''}&firstname=${firstname || ''}`;
    res.redirect(redirectUrl);
  });

  app.post("/api/payments/failure", (req: Request, res: Response) => {
    // PayU POST back to this URL upon failure
    const { txnid, amount, productinfo, udf1 } = req.body;
    console.log("PayU failure callback received:", req.body);
    
    // Redirect back to user.html with failed parameters
    const redirectUrl = `/user.html?paymentStatus=failure&txnid=${txnid || ''}&courseId=${productinfo || ''}&uid=${udf1 || ''}`;
    res.redirect(redirectUrl);
  });

  // Serve static assets in production, otherwise mount Vite in development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    // Serve HTML files properly
    app.get('/admin', (req, res) => {
      res.sendFile(path.join(distPath, 'admin.html'));
    });
    app.get('/user', (req, res) => {
      res.sendFile(path.join(distPath, 'user.html'));
    });
    // Fallback everything else to user.html
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'user.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Ed Achievers custom server running on port ${PORT}`);
  });
}

startServer();
