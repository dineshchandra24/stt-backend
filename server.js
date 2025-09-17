// backend/server.js
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import multer from "multer";
import mongoose from "mongoose";
import axios from "axios";
import PDFDocument from "pdfkit";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// --- Debug: confirm env loaded
console.log("DEEPGRAM_API_KEY loaded:", !!process.env.DEEPGRAM_API_KEY);
console.log("MONGO_URI loaded:", !!process.env.MONGO_URI);

// --- MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message || err);
  });

// --- Mongoose model
const historySchema = new mongoose.Schema({
  text: String,
  createdAt: { type: Date, default: Date.now },
});
const History = mongoose.model("History", historySchema);

// --- Multer memory storage so we can send buffer directly
const upload = multer({ storage: multer.memoryStorage() });

// --- Helper: determine a good mimetype for Deepgram
function chooseMimeType(file) {
  if (file?.mimetype && file.mimetype !== "application/octet-stream") {
    return file.mimetype;
  }
  const name = file?.originalname || "";
  const ext = name.split(".").pop()?.toLowerCase();
  const map = {
    wav: "audio/wav",
    mp3: "audio/mpeg",
    m4a: "audio/mp4",
    webm: "audio/webm",
    ogg: "audio/ogg",
  };
  return map[ext] || "audio/webm;codecs=opus";
}

// --- Helper: call Deepgram REST listen endpoint
async function transcribeWithDeepgram(buffer, mimetype) {
  if (!process.env.DEEPGRAM_API_KEY) {
    throw new Error("No Deepgram API key in environment");
  }
  const url = "https://api.deepgram.com/v1/listen?punctuate=true";

  try {
    const resp = await axios.post(url, buffer, {
      headers: {
        Authorization: `Token ${process.env.DEEPGRAM_API_KEY}`,
        "Content-Type": mimetype,
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 120000,
    });

    const data = resp.data;
    const alt =
      data?.results?.channels?.[0]?.alternatives?.[0] ||
      data?.results?.[0]?.alternatives?.[0] ||
      null;
    const transcript = alt?.transcript ?? null;

    return { transcript, raw: data };
  } catch (err) {
    const e = new Error("Deepgram request failed");
    e.details = {
      status: err?.response?.status,
      remoteData: err?.response?.data,
      message: err?.message,
    };
    throw e;
  }
}

// --- Transcription endpoint
app.post(["/transcribe", "/api/transcribe"], upload.single("audio"), async (req, res) => {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: "No audio file uploaded (field name must be 'audio')" });
    }

    console.log("Received file:", {
      originalname: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype,
    });

    const mimetype = chooseMimeType(req.file);
    const { transcript, raw } = await transcribeWithDeepgram(req.file.buffer, mimetype);

    console.log("Deepgram response (summary):", {
      transcriptExists: !!transcript,
      keys: raw ? Object.keys(raw) : null,
    });

    if (!transcript) {
      return res.status(500).json({
        error: "No transcript returned by Deepgram",
        deepgramRaw: raw,
      });
    }

    return res.json({ transcript });
  } catch (err) {
    console.error("Transcription error:", err.message || err);
    if (err.details) {
      console.error("Deepgram error details:", JSON.stringify(err.details, null, 2));
      return res.status(500).json({
        error: "Deepgram transcription failed",
        details: err.details,
      });
    }
    return res.status(500).json({ error: "Server transcription error", message: err.message });
  }
});

// --- History endpoints
app.post("/api/history", async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: "Empty text" });
    const item = new History({ text: text.trim() });
    await item.save();
    res.json(item);
  } catch (err) {
    console.error("Save history error:", err);
    res.status(500).json({ error: "Failed to save history" });
  }
});

app.get("/api/history", async (req, res) => {
  try {
    const items = await History.find().sort({ createdAt: -1 });
    res.json(items);
  } catch (err) {
    console.error("Fetch history error:", err);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

app.delete("/api/history", async (req, res) => {
  try {
    await History.deleteMany({});
    res.json({ success: true });
  } catch (err) {
    console.error("Clear history error:", err);
    res.status(500).json({ error: "Failed to clear history" });
  }
});

// ✅ NEW: Delete individual history item
app.delete("/api/history/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await History.findByIdAndDelete(id);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete history error:", err);
    res.status(500).json({ error: "Failed to delete history item" });
  }
});

// --- Download history
app.get("/api/history/download", async (req, res) => {
  try {
    const format = (req.query.format || req.query.type || "pdf").toLowerCase();
    const items = await History.find().sort({ createdAt: -1 });
    if (items.length === 0) return res.status(404).send("No history to download");

    if (format === "txt" || format === "text") {
      const content = items
        .map((it, i) => `${i + 1}. [${new Date(it.createdAt).toLocaleString()}]\n${it.text}`)
        .join("\n\n");
      res.setHeader("Content-Disposition", "attachment; filename=history.txt");
      res.setHeader("Content-Type", "text/plain");
      return res.send(content);
    }

    res.setHeader("Content-Disposition", "attachment; filename=history.pdf");
    res.setHeader("Content-Type", "application/pdf");

    const doc = new PDFDocument({ margin: 50 });
    doc.pipe(res);

    doc.fontSize(20).text("Transcription History", { align: "center" });
    doc.moveDown();

    items.forEach((it, idx) => {
      doc.fontSize(12).fillColor("black").text(`${idx + 1}. ${it.text}`, { paragraphGap: 4 });
      doc.fontSize(10).fillColor("gray").text(new Date(it.createdAt).toLocaleString(), { paragraphGap: 8 });
      doc.moveDown();
    });

    doc.end();
  } catch (err) {
    console.error("Download error:", err);
    res.status(500).json({ error: "Failed to generate download" });
  }
});

// --- simple health
app.get("/", (req, res) => res.send("✅ Backend running"));

// --- start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server listening on http://localhost:${PORT}`));
