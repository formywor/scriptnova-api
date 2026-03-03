const { Redis } = require("@upstash/redis");

function getRedis() {

  // Upstash KV integration variables
  const url =
    process.env.KV_REST_API_URL ||
    process.env.STORAGE_REDIS_REST_URL ||
    process.env.UPSTASH_REDIS_REST_URL ||
    "";

  const token =
    process.env.KV_REST_API_TOKEN ||
    process.env.STORAGE_REDIS_REST_TOKEN ||
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    "";

  if (!url || !token) {
    throw new Error("missing_redis_env");
  }

  return new Redis({
    url: url,
    token: token
  });
}

module.exports = { getRedis };