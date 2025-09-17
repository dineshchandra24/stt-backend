import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createClient } from "@deepgram/sdk";

// Fix __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const deepgram = createClient("fecca2db7756941e977c428874bff10122fb47b4");

async function testKey() {
  try {
    // Load the sample.wav we generated earlier
    const audio = fs.readFileSync(path.join(__dirname, "../sample.wav"));

    const { result } = await deepgram.listen.prerecorded.transcribeFile(audio, {
      model: "nova-2",
    });

    console.log("✅ API Key works!");
    console.log("Transcription:", result.results.channels[0].alternatives[0].transcript);
  } catch (err) {
    console.error("❌ API Key test failed:", err);
  }
}

testKey();
