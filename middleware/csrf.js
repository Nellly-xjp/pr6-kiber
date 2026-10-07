import crypto from "node:crypto";

export function csrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

export function verifyCsrf(req, res, next) {
  const token = req.body?._csrf;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) &&
      (!token || token !== req.session.csrfToken)) {
    return res.status(403).render("403", {
      message: "Недійсний або відсутній CSRF-токен."
    });
  }
  next();
}

export function verifyContentType(req, res, next) {
  if (req.method === "POST") {
    const contentType = req.headers["content-type"];
    if (!contentType || (
      !contentType.includes("application/x-www-form-urlencoded") &&
      !contentType.includes("application/json")
    )) {
      return res.status(400).render("500", {
        message: "Некоректний Content-Type запиту."
      });
    }
  }
  next();
}