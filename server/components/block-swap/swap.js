function swapMessageBlock(msg) {
  var _msg = JSON.parse(msg);
  if (_msg.content) {
    if (_msg.content.length > 32) {
      var firstBlock = _msg.content.slice(0, 16);
      var secondBlock = _msg.content.slice(16, 32);
      _msg.content = secondBlock + firstBlock + _msg.content.slice(32);
    }
  }
  _msg = JSON.stringify(_msg);
  return _msg;
}

module.exports = {
  swapMessageBlock: swapMessageBlock
};