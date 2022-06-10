const crypto = require('crypto');
const config = require('../config');
const storage = require('../storage');
const Limiter = require('../limiter');
const Stream = require('stream');

function id(user, kid) {
  const sha = crypto.createHash('sha256');
  sha.update(user.sub);
  sha.update(kid);
  const hash = sha.digest('hex');
  return `filelist-${hash}`;
}

module.exports = {
  async get(req, res) {
    const kid = req.params.id;
    try {
      const fileId = id(req.user, kid);
      const { length, stream } = await storage.get(fileId);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': length
      });
      stream.pipe(res);
    } catch (e) {
      res.sendStatus(404);
    }
  },

  async post(req, res) {
    const kid = req.params.id;
    try {
      const limiter = new Limiter(1024 * 1024 * 10);
      const inputStream = new Stream.Readable();
      inputStream.push(req.body);
      inputStream.push(null);
      const fileStream = inputStream.pipe(limiter);
      await storage.set(
        id(req.user, kid),
        fileStream,
        null,
        config.max_expire_seconds
      );
      res.sendStatus(200);
    } catch (e) {
      if (e.message === 'limit') {
        return res.sendStatus(413);
      }
      res.sendStatus(500);
    }
  }
};
