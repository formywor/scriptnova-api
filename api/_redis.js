const { Redis } = require("@upstash/redis");

function getRedis() {
  const url =
    process.env.STORAGE_REDIS_REST_URL ||
    process.env.UPSTASH_REDIS_REST_URL ||
    "";

  const token =
    process.env.STORAGE_REDIS_REST_TOKEN ||
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    "";

  if (!url || !token) throw new Error("missing_redis_env");

  return new Redis({ url, token });
}

module.exports = { getRedis };