function swapIvBlock(msg) {
  
  var _msg = JSON.parse(msg);
  var _iv = new Buffer(_msg.iv);
  
  var value = _iv[2];
  value = value + 2;
  if (value > 255){
    value -= 255;
  }
  
  _iv[2] = value;
  
  _msg.iv = _iv;
  
  return JSON.stringify(_msg);
  
}

module.exports = {
  swapMessageBlock: swapIvBlock
};