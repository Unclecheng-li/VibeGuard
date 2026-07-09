import type { PackageRegistry } from "../types";

export const knownPackages: Record<"npm" | "pypi", string[]> = {
  npm: [
    "@angular/core",
    "@nestjs/common",
    "@reduxjs/toolkit",
    "@types/node",
    "axios",
    "bcrypt",
    "chalk",
    "commander",
    "cors",
    "dotenv",
    "express",
    "express-rate-limit",
    "fastify",
    "jsonwebtoken",
    "lodash",
    "mongoose",
    "next",
    "next-auth",
    "node-fetch",
    "pg",
    "prisma",
    "react",
    "react-dom",
    "react-router-dom",
    "react-virtualized",
    "react-window",
    "sqlite3",
    "typescript",
    "vite",
    "vue",
    "zod"
  ],
  pypi: [
    "boto3",
    "celery",
    "django",
    "fastapi",
    "flask",
    "httpx",
    "jinja2",
    "numpy",
    "openai",
    "pandas",
    "pillow",
    "opencv-python",
    "psycopg2",
    "pydantic",
    "pytest",
    "python-dotenv",
    "pyyaml",
    "requests",
    "scikit-learn",
    "sqlalchemy",
    "torch",
    "torchvision",
    "transformers",
    "uvicorn",
    "slowapi",
    "fastapi-limiter",
    "django-allauth"
  ]
};

export const knownHallucinatedPackages: Record<"npm" | "pypi", Record<string, string[]>> = {
  npm: {
    "react-virtualized-auto-sizer": ["react-virtualized", "react-window"],
    "express-rate-limit-flex": ["express-rate-limit"],
    "secure-jwt-auth": ["jsonwebtoken"],
    "next-auth-middleware-secure": ["next-auth"],
    "openai-vision-client": ["openai"]
  },
  pypi: {
    "torch-vision-utils": ["torchvision", "torch"],
    "fastapi-limiter-middleware": ["slowapi", "fastapi-limiter"],
    "django-secure-auth": ["django-allauth", "django"],
    "openai-secret-manager": ["openai", "python-dotenv"],
    "pandas-ai-utils": ["pandas"]
  }
};

export const packageAliases: Record<string, string> = {
  PIL: "pillow",
  cv2: "opencv-python",
  sklearn: "scikit-learn",
  dotenv: "python-dotenv",
  yaml: "pyyaml"
};

export function seedExists(registry: PackageRegistry, packageName: string): boolean | undefined {
  if (registry !== "npm" && registry !== "pypi") {
    return undefined;
  }
  const normalized = packageName.toLowerCase();
  if (knownPackages[registry].some((name) => name.toLowerCase() === normalized)) {
    return true;
  }
  if (Object.keys(knownHallucinatedPackages[registry]).some((name) => name.toLowerCase() === normalized)) {
    return false;
  }
  return undefined;
}

export function seedSuggestions(registry: PackageRegistry, packageName: string): string[] {
  if (registry !== "npm" && registry !== "pypi") {
    return [];
  }
  const lowerName = packageName.toLowerCase();
  const direct = Object.entries(knownHallucinatedPackages[registry]).find(([name]) => name.toLowerCase() === lowerName);
  if (direct) {
    return direct[1];
  }

  return knownPackages[registry]
    .map((candidate) => ({
      candidate,
      distance: levenshtein(lowerName, candidate.toLowerCase())
    }))
    .filter((entry) => entry.distance <= 3 || entry.candidate.toLowerCase().includes(lowerName))
    .sort((a, b) => a.distance - b.distance || a.candidate.localeCompare(b.candidate))
    .slice(0, 3)
    .map((entry) => entry.candidate);
}

function levenshtein(a: string, b: string): number {
  const previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  const current = new Array<number>(b.length + 1);

  for (let i = 1; i <= a.length; i += 1) {
    current[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j += 1) {
      previous[j] = current[j];
    }
  }

  return previous[b.length];
}
