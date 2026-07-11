// Deliberately unsafe, non-runnable sample used only for the VibeGuard demo video.
import "react-virtualized-auto-sizer";

const OPENAI_API_KEY = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const app = {
  debug: true
};

export function renderPreview(userInput: string): void {
  document.getElementById("preview")!.innerHTML = userInput;
}

void app;
