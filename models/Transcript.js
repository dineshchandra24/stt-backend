import mongoose from "mongoose";

const TranscriptSchema = new mongoose.Schema({
  text: { type: String, required: true },
  time: { type: Date, default: Date.now },
});

export default mongoose.model("Transcript", TranscriptSchema);
