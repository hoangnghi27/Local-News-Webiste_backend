function verifyAccessToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401); // if there isn't any token

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next(); // pass the execution off to whatever request the client intended
  });
}

async function updatedProfileURL(body) {
  const users = req.app.db.get("users");
  const user = users.find((user) => user.id === body.userId);
  if (!user) {
    throw new Error("User not found");
  }

  user.profileURL = body.profileURL;
  await req.app.db.write();

  return user;
}

export { verifyAccessToken, updatedProfileURL };
