import ModelClient, { isUnexpected } from "@azure-rest/ai-inference";
import { AzureKeyCredential } from "@azure/core-auth";
import fs from "fs";
import path from "path";

const token = process.env["GITHUB_TOKEN"];
const endpoint = "https://models.github.ai/inference";
const model = "openai/gpt-4.1";

// Hardcode the image filename
const inputImage = "contoso_layout_sketch.jpg";

export async function main() {
  if (!token) {
    throw new Error("GITHUB_TOKEN environment variable is not set.");
  }

  const imagePath = path.join(process.cwd(), inputImage);
  if (!fs.existsSync(imagePath)) {
    throw new Error(`Image file not found: ${imagePath}`);
  }
  const imageBuffer = fs.readFileSync(imagePath);
  const base64Image = imageBuffer.toString("base64");

  const client = ModelClient(
    endpoint,
    new AzureKeyCredential(token)
  );

  const response = await client.path("/chat/completions").post({
    body: {
      messages: [
        { role:"system", content: "You are a frontend developer who likes to turn sketches into real webpages." },
        { role:"user", content: "Write HTML and CSS code for a web page based on the following hand-drawn sketch." },
        {
          role: "user",
          content: "",
          type: "image_url",
          image_url: {
            url: `data:image/jpeg;base64,${base64Image}`
          },
        }
      ],
      temperature: 1.0,
      top_p: 1.0,
      max_tokens: 1000,
      model: model
    }
  });

  if (isUnexpected(response)) {
    console.error("API Error Response:", response.body);
    throw new Error(JSON.stringify(response.body?.error || response.body));
  }

  if (
    !response.body ||
    !response.body.choices ||
    !response.body.choices[0] ||
    !response.body.choices[0].message ||
    !response.body.choices[0].message.content
  ) {
    console.error("Unexpected API response format:", response.body);
    throw new Error("API response missing expected content.");
  }

  console.log(response.body.choices[0].message.content);
}

main().catch((err) => {
  console.error("The sample encountered an error:", err);
});
