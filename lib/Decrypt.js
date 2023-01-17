var Int64 = require('node-int64');
var Stream = require('stream');

// Backwards compatibility for node versions < 8
if (!Stream.Writable || !Stream.Writable.prototype.destroy)
  Stream = require('readable-stream');

var table;

function generateTable() {
  var poly = 0xEDB88320,c,n,k;
  table = [];
  for (n = 0; n < 256; n++) {
    c = n;
    for (k = 0; k < 8; k++)
      c = (c & 1) ? poly ^ (c >>> 1) :  c = c >>> 1;
    table[n] = c >>> 0;
  }
}

function crc(ch,crc) {
  if (!table)
    generateTable();

  if (ch.charCodeAt)
    ch = ch.charCodeAt(0);   
    
  var l = (crc.readUInt32BE() >> 8) & 0xffffff;
  var r = table[(crc.readUInt32BE() ^ (ch >>> 0)) & 0xff];

  return (l ^ r) >>> 0;
}

function multiply(a, b) {
  var ah = (a >> 16) & 0xffff;
  var al = a & 0xffff;
  var bh = (b >> 16) & 0xffff;
  var bl = b & 0xffff;
  var high = (ah * bl + al * bh) & 0xffff;
  return ((high << 16) >>> 0) + al * bl;
};

function Decrypt() {
  if (!(this instanceof Decrypt))
    return new Decrypt();

  this.key0 = Buffer.allocUnsafe(4);
  this.key1 = Buffer.allocUnsafe(4);
  this.key2 = Buffer.allocUnsafe(4);

  this.key0.writeUInt32BE(0x12345678, 0);
  this.key1.writeUInt32BE(0x23456789, 0);
  this.key2.writeUInt32BE(0x34567890, 0);
}

Decrypt.prototype.update = function(h) {            
  this.key0.writeUInt32BE(crc(h,this.key0));
  this.key1.writeUInt32BE(((this.key0.readUInt32BE() & 0xff & 0xFFFFFFFF) + this.key1.readUInt32BE()) >>> 0);

  var x = new Int64((multiply(this.key1.readUInt32BE(), 134775813) + 1) & 0xFFFFFFFF);
  var b = Buffer.alloc(8);
  x.copy(b, 0);
  b.copy(this.key1, 0, 4, 8);

  this.key2.writeUInt32BE(crc(((this.key1.readUInt32BE() >> 24) & 0xff) >>> 0, this.key2));
}

Decrypt.prototype.decryptByte = function(c) {
  var k = (this.key2.readUInt32BE() | 2) >>> 0;
  c = c ^ ((multiply(k, (k^1 >>> 0)) >> 8) & 0xff);
  this.update(c);
  return c;
};

 Decrypt.prototype.stream = function() {
  var stream = Stream.Transform(),
      self = this;

  stream._transform = function(d,e,cb) {
    for (var i = 0; i<d.length;i++) {
      d[i] = self.decryptByte(d[i]);
    }
    this.push(d);
    cb();
  };
  return stream;
};

module.exports = Decrypt;