import type { PackageRegistry } from "../types";

export const knownPackages: Record<PackageRegistry, string[]> = {
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
  ],
  cargo: [
    "actix-web",
    "anyhow",
    "axum",
    "chrono",
    "clap",
    "diesel",
    "rand",
    "regex",
    "reqwest",
    "serde",
    "serde_json",
    "sqlx",
    "thiserror",
    "tokio",
    "tracing",
    "uuid"
  ],
  gomod: [
    "github.com/gin-gonic/gin",
    "github.com/go-chi/chi",
    "github.com/golang-jwt/jwt/v5",
    "github.com/gorilla/mux",
    "github.com/jackc/pgx/v5",
    "github.com/labstack/echo/v4",
    "github.com/redis/go-redis/v9",
    "github.com/spf13/cobra",
    "github.com/stretchr/testify",
    "go.mongodb.org/mongo-driver",
    "go.uber.org/zap",
    "golang.org/x/crypto",
    "google.golang.org/grpc",
    "gorm.io/gorm"
  ],
  maven: [
    "ch.qos.logback:logback-classic",
    "com.fasterxml.jackson.core:jackson-databind",
    "com.google.guava:guava",
    "com.squareup.okhttp3:okhttp",
    "io.jsonwebtoken:jjwt-api",
    "jakarta.validation:jakarta.validation-api",
    "junit:junit",
    "org.apache.commons:commons-lang3",
    "org.hibernate.validator:hibernate-validator",
    "org.junit.jupiter:junit-jupiter",
    "org.postgresql:postgresql",
    "org.springframework.boot:spring-boot-starter-data-jpa",
    "org.springframework.boot:spring-boot-starter-security",
    "org.springframework.boot:spring-boot-starter-web",
    "org.springframework.security:spring-security-core"
  ]
};

export const knownHallucinatedPackages: Record<PackageRegistry, Record<string, string[]>> = {
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
  },
  cargo: {
    "actix-web-secure-middleware": ["actix-web"],
    "axum-auth-guard": ["axum"],
    "reqwest-retry-plus": ["reqwest"],
    "serde-secure-json": ["serde", "serde_json"],
    "tokio-secure-auth": ["tokio"]
  },
  gomod: {
    "github.com/gin-gonic/secure-gin": ["github.com/gin-gonic/gin"],
    "github.com/gorilla/secure-mux": ["github.com/gorilla/mux"],
    "github.com/spf13/secure-cobra": ["github.com/spf13/cobra"],
    "golang.org/x/securecrypto": ["golang.org/x/crypto"],
    "gorm.io/secure-gorm": ["gorm.io/gorm"]
  },
  maven: {
    "com.fasterxml.jackson.core:jackson-databind-secure": ["com.fasterxml.jackson.core:jackson-databind"],
    "io.jsonwebtoken:jjwt-secure-api": ["io.jsonwebtoken:jjwt-api"],
    "org.postgresql:postgresql-secure": ["org.postgresql:postgresql"],
    "org.springframework.boot:spring-boot-starter-secure-api": ["org.springframework.boot:spring-boot-starter-security"],
    "org.springframework.security:spring-security-auth-magic": ["org.springframework.security:spring-security-core"]
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
