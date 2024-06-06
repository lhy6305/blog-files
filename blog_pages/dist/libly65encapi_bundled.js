!function(){function F(){}var W,n,l,e,a,P,j,T,J,s,L,X,I,U,q,i,K,$,G,Q,c,r,V,Y,Z,tt,et,nt,rt,it;function t(){return o.create.apply(o,arguments)}l=Math,h=(d={}).lib={},e=h.Base={extend:function(t){F.prototype=this;var e=new F;return t&&e.mixIn(t),e.hasOwnProperty("init")||(e.init=function(){e.$super.init.apply(this,arguments)}),(e.init.prototype=e).$super=this,e},create:function(){var t=this.extend();return t.init.apply(t,arguments),t},init:function(){},mixIn:function(t){for(var e in t)t.hasOwnProperty(e)&&(this[e]=t[e]);t.hasOwnProperty("toString")&&(this.toString=t.toString)},clone:function(){return this.init.prototype.extend(this)}},a=h.WordArray=e.extend({init:function(t,e){t=this.words=t||[],this.sigBytes=null!=e?e:4*t.length},toString:function(t){return(t||P).stringify(this)},concat:function(t){var e=this.words,n=t.words,r=this.sigBytes;if(t=t.sigBytes,this.clamp(),r%4)for(var i=0;i<t;i++)e[r+i>>>2]|=(n[i>>>2]>>>24-i%4*8&255)<<24-(r+i)%4*8;else if(65535<n.length)for(i=0;i<t;i+=4)e[r+i>>>2]=n[i>>>2];else e.push.apply(e,n);return this.sigBytes+=t,this},clamp:function(){var t=this.words,e=this.sigBytes;t[e>>>2]&=4294967295<<32-e%4*8,t.length=l.ceil(e/4)},clone:function(){var t=e.clone.call(this);return t.words=this.words.slice(0),t},random:function(t){for(var e=[],n=0;n<t;n+=4)e.push(4294967296*l.random()|0);return new a.init(e,t)}}),p=d.enc={},P=p.Hex={stringify:function(t){var e=t.words;t=t.sigBytes;for(var n=[],r=0;r<t;r++){var i=e[r>>>2]>>>24-r%4*8&255;n.push((i>>>4).toString(16)),n.push((15&i).toString(16))}return n.join("")},parse:function(t){for(var e=t.length,n=[],r=0;r<e;r+=2)n[r>>>3]|=parseInt(t.substr(r,2),16)<<24-r%8*4;return new a.init(n,e/2)}},j=p.Latin1={stringify:function(t){var e=t.words;t=t.sigBytes;for(var n=[],r=0;r<t;r++)n.push(String.fromCharCode(e[r>>>2]>>>24-r%4*8&255));return n.join("")},parse:function(t){for(var e=t.length,n=[],r=0;r<e;r++)n[r>>>2]|=(255&t.charCodeAt(r))<<24-r%4*8;return new a.init(n,e)}},T=p.Utf8={stringify:function(t){try{return decodeURIComponent(escape(j.stringify(t)))}catch(e){throw Error("Malformed UTF-8 data")}},parse:function(t){return j.parse(unescape(encodeURIComponent(t)))}},J=h.BufferedBlockAlgorithm=e.extend({reset:function(){this._data=new a.init,this._nDataBytes=0},_append:function(t){"string"==typeof t&&(t=T.parse(t)),this._data.concat(t),this._nDataBytes+=t.sigBytes},_process:function(t){var e=this._data,n=e.words,r=e.sigBytes,i=this.blockSize,o=r/(4*i),o=t?l.ceil(o):l.max((0|o)-this._minBufferSize,0),r=l.min(4*(t=o*i),r);if(t){for(var s=0;s<t;s+=i)this._doProcessBlock(n,s);s=n.splice(0,t),e.sigBytes-=r}return new a.init(s,r)},clone:function(){var t=e.clone.call(this);return t._data=this._data.clone(),t},_minBufferSize:0}),h.Hasher=J.extend({cfg:e.extend(),init:function(t){this.cfg=this.cfg.extend(t),this.reset()},reset:function(){J.reset.call(this),this._doReset()},update:function(t){return this._append(t),this._process(),this},finalize:function(t){return t&&this._append(t),this._doFinalize()},blockSize:16,_createHelper:function(n){return function(t,e){return new n.init(e).finalize(t)}},_createHmacHelper:function(n){return function(t,e){return new W.HMAC.init(n,e).finalize(t)}}}),W=d.algo={},h=(p=n=d).lib,rt=h.Base,it=h.WordArray,(p=p.x64={}).Word=rt.extend({init:function(t,e){this.high=t,this.low=e}}),p.WordArray=rt.extend({init:function(t,e){t=this.words=t||[],this.sigBytes=null!=e?e:8*t.length},toX32:function(){for(var t=this.words,e=t.length,n=[],r=0;r<e;r++){var i=t[r];n.push(i.high),n.push(i.low)}return it.create(n,this.sigBytes)},clone:function(){for(var t=rt.clone.call(this),e=t.words=this.words.slice(0),n=e.length,r=0;r<n;r++)e[r]=e[r].clone();return t}});for(var ot=(d=n).lib.Hasher,o=(h=d.x64).Word,st=h.WordArray,h=d.algo,at=[t(1116352408,3609767458),t(1899447441,602891725),t(3049323471,3964484399),t(3921009573,2173295548),t(961987163,4081628472),t(1508970993,3053834265),t(2453635748,2937671579),t(2870763221,3664609560),t(3624381080,2734883394),t(310598401,1164996542),t(607225278,1323610764),t(1426881987,3590304994),t(1925078388,4068182383),t(2162078206,991336113),t(2614888103,633803317),t(3248222580,3479774868),t(3835390401,2666613458),t(4022224774,944711139),t(264347078,2341262773),t(604807628,2007800933),t(770255983,1495990901),t(1249150122,1856431235),t(1555081692,3175218132),t(1996064986,2198950837),t(2554220882,3999719339),t(2821834349,766784016),t(2952996808,2566594879),t(3210313671,3203337956),t(3336571891,1034457026),t(3584528711,2466948901),t(113926993,3758326383),t(338241895,168717936),t(666307205,1188179964),t(773529912,1546045734),t(1294757372,1522805485),t(1396182291,2643833823),t(1695183700,2343527390),t(1986661051,1014477480),t(2177026350,1206759142),t(2456956037,344077627),t(2730485921,1290863460),t(2820302411,3158454273),t(3259730800,3505952657),t(3345764771,106217008),t(3516065817,3606008344),t(3600352804,1432725776),t(4094571909,1467031594),t(275423344,851169720),t(430227734,3100823752),t(506948616,1363258195),t(659060556,3750685593),t(883997877,3785050280),t(958139571,3318307427),t(1322822218,3812723403),t(1537002063,2003034995),t(1747873779,3602036899),t(1955562222,1575990012),t(2024104815,1125592928),t(2227730452,2716904306),t(2361852424,442776044),t(2428436474,593698344),t(2756734187,3733110249),t(3204031479,2999351573),t(3329325298,3815920427),t(3391569614,3928383900),t(3515267271,566280711),t(3940187606,3454069534),t(4118630271,4000239992),t(116418474,1914138554),t(174292421,2731055270),t(289380356,3203993006),t(460393269,320620315),t(685471733,587496836),t(852142971,1086792851),t(1017036298,365543100),t(1126000580,2618297676),t(1288033470,3409855158),t(1501505948,4234509866),t(1607167915,987167468),t(1816402316,1246189591)],ct=[],lt=0;lt<80;lt++)ct[lt]=t();h=h.SHA512=ot.extend({_doReset:function(){this._hash=new st.init([new o.init(1779033703,4089235720),new o.init(3144134277,2227873595),new o.init(1013904242,4271175723),new o.init(2773480762,1595750129),new o.init(1359893119,2917565137),new o.init(2600822924,725511199),new o.init(528734635,4215389547),new o.init(1541459225,327033209)])},_doProcessBlock:function(F,W){for(var t=(a=this._hash.words)[0],e=a[1],n=a[2],r=a[3],i=a[4],o=a[5],s=a[6],a=a[7],P=t.high,c=t.low,j=e.high,l=e.low,T=n.high,h=n.low,J=r.high,d=r.low,L=i.high,p=i.low,X=o.high,u=o.low,I=s.high,f=s.low,U=a.high,y=a.low,g=P,_=c,w=j,v=l,m=T,k=h,q=J,B=d,S=L,x=p,K=X,b=u,$=I,C=f,G=U,Q=y,A=0;A<80;A++)var H,z=ct[A],V=(A<16?(H=z.high=0|F[W+2*A],R=z.low=0|F[W+2*A+1]):(H=((R=(H=ct[A-15]).high)>>>1|(E=H.low)<<31)^(R>>>8|E<<24)^R>>>7,E=(E>>>1|R<<31)^(E>>>8|R<<24)^(E>>>7|R<<25),D=((R=(D=ct[A-2]).high)>>>19|(O=D.low)<<13)^(R<<3|O>>>29)^R>>>6,O=(O>>>19|R<<13)^(O<<3|R>>>29)^(O>>>6|R<<26),V=(R=ct[A-7]).high,N=(M=ct[A-16]).high,M=M.low,H=(H=(H=H+V+((R=E+R.low)>>>0<E>>>0?1:0))+D+((R+=O)>>>0<O>>>0?1:0))+N+((R+=M)>>>0<M>>>0?1:0),z.high=H,z.low=R),S&K^~S&$),M=x&b^~x&C,z=g&w^g&m^w&m,E=(g>>>28|_<<4)^(g<<30|_>>>2)^(g<<25|_>>>7),D=(_>>>28|g<<4)^(_<<30|g>>>2)^(_<<25|g>>>7),O=at[A],Y=O.high,Z=O.low,N=(N=(N=(N=G+((S>>>14|x<<18)^(S>>>18|x<<14)^(S<<23|x>>>9))+((O=Q+((x>>>14|S<<18)^(x>>>18|S<<14)^(x<<23|S>>>9)))>>>0<Q>>>0?1:0))+V+((O+=M)>>>0<M>>>0?1:0))+Y+((O+=Z)>>>0<Z>>>0?1:0))+H+((O+=R)>>>0<R>>>0?1:0),R=D+(_&v^_&k^v&k),G=$,Q=C,$=K,C=b,K=S,b=x,S=q+N+((x=B+O|0)>>>0<B>>>0?1:0)|0,q=m,B=k,m=w,k=v,w=g,v=_,g=N+(z=E+z+(R>>>0<D>>>0?1:0))+((_=O+R|0)>>>0<O>>>0?1:0)|0;c=t.low=c+_,t.high=P+g+(c>>>0<_>>>0?1:0),l=e.low=l+v,e.high=j+w+(l>>>0<v>>>0?1:0),h=n.low=h+k,n.high=T+m+(h>>>0<k>>>0?1:0),d=r.low=d+B,r.high=J+q+(d>>>0<B>>>0?1:0),p=i.low=p+x,i.high=L+S+(p>>>0<x>>>0?1:0),u=o.low=u+b,o.high=X+K+(u>>>0<b>>>0?1:0),f=s.low=f+C,s.high=I+$+(f>>>0<C>>>0?1:0),y=a.low=y+Q,a.high=U+G+(y>>>0<Q>>>0?1:0)},_doFinalize:function(){var t=this._data,e=t.words,n=8*this._nDataBytes,r=8*t.sigBytes;return e[r>>>5]|=128<<24-r%32,e[30+(128+r>>>10<<5)]=Math.floor(n/4294967296),e[31+(128+r>>>10<<5)]=n,t.sigBytes=4*e.length,this._process(),this._hash.toX32()},clone:function(){var t=ot.clone.call(this);return t._hash=this._hash.clone(),t},blockSize:32}),d.SHA512=ot._createHelper(h),d.HmacSHA512=ot._createHmacHelper(h);var ht=Math;function dt(t){return 4294967296*(t-(0|t))|0}for(var pt=(d=(p=n).lib).WordArray,ut=d.Hasher,d=p.algo,ft=[],yt=[],gt=2,_t=0;_t<64;){t:{for(var wt=gt,vt=ht.sqrt(wt),mt=2;mt<=vt;mt++)if(!(wt%mt)){wt=!1;break t}wt=!0}wt&&(_t<8&&(ft[_t]=dt(ht.pow(gt,.5))),yt[_t]=dt(ht.pow(gt,1/3)),_t++),gt++}var kt=[],d=d.SHA256=ut.extend({_doReset:function(){this._hash=new pt.init(ft.slice(0))},_doProcessBlock:function(t,e){for(var n,r,i=this._hash.words,o=i[0],s=i[1],a=i[2],c=i[3],l=i[4],h=i[5],d=i[6],p=i[7],u=0;u<64;u++)kt[u]=u<16?0|t[e+u]:(((n=kt[u-15])<<25|n>>>7)^(n<<14|n>>>18)^n>>>3)+kt[u-7]+(((r=kt[u-2])<<15|r>>>17)^(r<<13|r>>>19)^r>>>10)+kt[u-16],n=p+((l<<26|l>>>6)^(l<<21|l>>>11)^(l<<7|l>>>25))+(l&h^~l&d)+yt[u]+kt[u],r=((o<<30|o>>>2)^(o<<19|o>>>13)^(o<<10|o>>>22))+(o&s^o&a^s&a),p=d,d=h,h=l,l=c+n|0,c=a,a=s,s=o,o=n+r|0;i[0]=i[0]+o|0,i[1]=i[1]+s|0,i[2]=i[2]+a|0,i[3]=i[3]+c|0,i[4]=i[4]+l|0,i[5]=i[5]+h|0,i[6]=i[6]+d|0,i[7]=i[7]+p|0},_doFinalize:function(){var t=this._data,e=t.words,n=8*this._nDataBytes,r=8*t.sigBytes;return e[r>>>5]|=128<<24-r%32,e[14+(64+r>>>9<<4)]=ht.floor(n/4294967296),e[15+(64+r>>>9<<4)]=n,t.sigBytes=4*e.length,this._process(),this._hash},clone:function(){var t=ut.clone.call(this);return t._hash=this._hash.clone(),t}}),Bt=(p.SHA256=ut._createHelper(d),p.HmacSHA256=ut._createHmacHelper(d),Math);function S(t,e,n,r,i,o,s){return((t=t+(e&n|~e&r)+i+s)<<o|t>>>32-o)+e}function x(t,e,n,r,i,o,s){return((t=t+(e&r|n&~r)+i+s)<<o|t>>>32-o)+e}function b(t,e,n,r,i,o,s){return((t=t+(e^n^r)+i+s)<<o|t>>>32-o)+e}function C(t,e,n,r,i,o,s){return((t=t+(n^(e|~r))+i+s)<<o|t>>>32-o)+e}for(var St=(p=(h=n).lib).WordArray,xt=p.Hasher,p=h.algo,A=[],bt=0;bt<64;bt++)A[bt]=4294967296*Bt.abs(Bt.sin(bt+1))|0;p=p.MD5=xt.extend({_doReset:function(){this._hash=new St.init([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(t,e){for(var n=0;n<16;n++){var r=t[i=e+n];t[i]=16711935&(r<<8|r>>>24)|4278255360&(r<<24|r>>>8)}var n=this._hash.words,i=t[e+0],r=t[e+1],o=t[e+2],s=t[e+3],a=t[e+4],c=t[e+5],l=t[e+6],h=t[e+7],d=t[e+8],p=t[e+9],u=t[e+10],f=t[e+11],y=t[e+12],g=t[e+13],_=t[e+14],w=t[e+15],v=S(n[0],B=n[1],k=n[2],m=n[3],i,7,A[0]),m=S(m,v,B,k,r,12,A[1]),k=S(k,m,v,B,o,17,A[2]),B=S(B,k,m,v,s,22,A[3]),v=S(v,B,k,m,a,7,A[4]),m=S(m,v,B,k,c,12,A[5]),k=S(k,m,v,B,l,17,A[6]),B=S(B,k,m,v,h,22,A[7]),v=S(v,B,k,m,d,7,A[8]),m=S(m,v,B,k,p,12,A[9]),k=S(k,m,v,B,u,17,A[10]),B=S(B,k,m,v,f,22,A[11]),v=S(v,B,k,m,y,7,A[12]),m=S(m,v,B,k,g,12,A[13]),k=S(k,m,v,B,_,17,A[14]),v=x(v,B=S(B,k,m,v,w,22,A[15]),k,m,r,5,A[16]),m=x(m,v,B,k,l,9,A[17]),k=x(k,m,v,B,f,14,A[18]),B=x(B,k,m,v,i,20,A[19]),v=x(v,B,k,m,c,5,A[20]),m=x(m,v,B,k,u,9,A[21]),k=x(k,m,v,B,w,14,A[22]),B=x(B,k,m,v,a,20,A[23]),v=x(v,B,k,m,p,5,A[24]),m=x(m,v,B,k,_,9,A[25]),k=x(k,m,v,B,s,14,A[26]),B=x(B,k,m,v,d,20,A[27]),v=x(v,B,k,m,g,5,A[28]),m=x(m,v,B,k,o,9,A[29]),k=x(k,m,v,B,h,14,A[30]),v=b(v,B=x(B,k,m,v,y,20,A[31]),k,m,c,4,A[32]),m=b(m,v,B,k,d,11,A[33]),k=b(k,m,v,B,f,16,A[34]),B=b(B,k,m,v,_,23,A[35]),v=b(v,B,k,m,r,4,A[36]),m=b(m,v,B,k,a,11,A[37]),k=b(k,m,v,B,h,16,A[38]),B=b(B,k,m,v,u,23,A[39]),v=b(v,B,k,m,g,4,A[40]),m=b(m,v,B,k,i,11,A[41]),k=b(k,m,v,B,s,16,A[42]),B=b(B,k,m,v,l,23,A[43]),v=b(v,B,k,m,p,4,A[44]),m=b(m,v,B,k,y,11,A[45]),k=b(k,m,v,B,w,16,A[46]),v=C(v,B=b(B,k,m,v,o,23,A[47]),k,m,i,6,A[48]),m=C(m,v,B,k,h,10,A[49]),k=C(k,m,v,B,_,15,A[50]),B=C(B,k,m,v,c,21,A[51]),v=C(v,B,k,m,y,6,A[52]),m=C(m,v,B,k,s,10,A[53]),k=C(k,m,v,B,u,15,A[54]),B=C(B,k,m,v,r,21,A[55]),v=C(v,B,k,m,d,6,A[56]),m=C(m,v,B,k,w,10,A[57]),k=C(k,m,v,B,l,15,A[58]),B=C(B,k,m,v,g,21,A[59]),v=C(v,B,k,m,a,6,A[60]),m=C(m,v,B,k,f,10,A[61]),k=C(k,m,v,B,o,15,A[62]),B=C(B,k,m,v,p,21,A[63]);n[0]=n[0]+v|0,n[1]=n[1]+B|0,n[2]=n[2]+k|0,n[3]=n[3]+m|0},_doFinalize:function(){var t=this._data,e=t.words,n=8*this._nDataBytes,r=8*t.sigBytes,i=(e[r>>>5]|=128<<24-r%32,Bt.floor(n/4294967296));for(e[15+(64+r>>>9<<4)]=16711935&(i<<8|i>>>24)|4278255360&(i<<24|i>>>8),e[14+(64+r>>>9<<4)]=16711935&(n<<8|n>>>24)|4278255360&(n<<24|n>>>8),t.sigBytes=4*(e.length+1),this._process(),e=(t=this._hash).words,n=0;n<4;n++)r=e[n],e[n]=16711935&(r<<8|r>>>24)|4278255360&(r<<24|r>>>8);return t},clone:function(){var t=xt.clone.call(this);return t._hash=this._hash.clone(),t}}),h.MD5=xt._createHelper(p),h.HmacMD5=xt._createHmacHelper(p),n=n||(c=Math,h=(d={}).lib={},r=h.Base={extend:function(t){Zt.prototype=this;var e=new Zt;return t&&e.mixIn(t),e.hasOwnProperty("init")||(e.init=function(){e.$super.init.apply(this,arguments)}),(e.init.prototype=e).$super=this,e},create:function(){var t=this.extend();return t.init.apply(t,arguments),t},init:function(){},mixIn:function(t){for(var e in t)t.hasOwnProperty(e)&&(this[e]=t[e]);t.hasOwnProperty("toString")&&(this.toString=t.toString)},clone:function(){return this.init.prototype.extend(this)}},V=h.WordArray=r.extend({init:function(t,e){t=this.words=t||[],this.sigBytes=null!=e?e:4*t.length},toString:function(t){return(t||Y).stringify(this)},concat:function(t){var e=this.words,n=t.words,r=this.sigBytes;if(t=t.sigBytes,this.clamp(),r%4)for(var i=0;i<t;i++)e[r+i>>>2]|=(n[i>>>2]>>>24-i%4*8&255)<<24-(r+i)%4*8;else if(65535<n.length)for(i=0;i<t;i+=4)e[r+i>>>2]=n[i>>>2];else e.push.apply(e,n);return this.sigBytes+=t,this},clamp:function(){var t=this.words,e=this.sigBytes;t[e>>>2]&=4294967295<<32-e%4*8,t.length=c.ceil(e/4)},clone:function(){var t=r.clone.call(this);return t.words=this.words.slice(0),t},random:function(t){for(var e=[],n=0;n<t;n+=4)e.push(4294967296*c.random()|0);return new V.init(e,t)}}),p=d.enc={},Y=p.Hex={stringify:function(t){var e=t.words;t=t.sigBytes;for(var n=[],r=0;r<t;r++){var i=e[r>>>2]>>>24-r%4*8&255;n.push((i>>>4).toString(16)),n.push((15&i).toString(16))}return n.join("")},parse:function(t){for(var e=t.length,n=[],r=0;r<e;r+=2)n[r>>>3]|=parseInt(t.substr(r,2),16)<<24-r%8*4;return new V.init(n,e/2)}},Z=p.Latin1={stringify:function(t){var e=t.words;t=t.sigBytes;for(var n=[],r=0;r<t;r++)n.push(String.fromCharCode(e[r>>>2]>>>24-r%4*8&255));return n.join("")},parse:function(t){for(var e=t.length,n=[],r=0;r<e;r++)n[r>>>2]|=(255&t.charCodeAt(r))<<24-r%4*8;return new V.init(n,e)}},tt=p.Utf8={stringify:function(t){try{return decodeURIComponent(escape(Z.stringify(t)))}catch(e){throw Error("Malformed UTF-8 data")}},parse:function(t){return Z.parse(unescape(encodeURIComponent(t)))}},et=h.BufferedBlockAlgorithm=r.extend({reset:function(){this._data=new V.init,this._nDataBytes=0},_append:function(t){"string"==typeof t&&(t=tt.parse(t)),this._data.concat(t),this._nDataBytes+=t.sigBytes},_process:function(t){var e=this._data,n=e.words,r=e.sigBytes,i=this.blockSize,o=r/(4*i),o=t?c.ceil(o):c.max((0|o)-this._minBufferSize,0),r=c.min(4*(t=o*i),r);if(t){for(var s=0;s<t;s+=i)this._doProcessBlock(n,s);s=n.splice(0,t),e.sigBytes-=r}return new V.init(s,r)},clone:function(){var t=r.clone.call(this);return t._data=this._data.clone(),t},_minBufferSize:0}),h.Hasher=et.extend({cfg:r.extend(),init:function(t){this.cfg=this.cfg.extend(t),this.reset()},reset:function(){et.reset.call(this),this._doReset()},update:function(t){return this._append(t),this._process(),this},finalize:function(t){return t&&this._append(t),this._doFinalize()},blockSize:16,_createHelper:function(n){return function(t,e){return new n.init(e).finalize(t)}},_createHmacHelper:function(n){return function(t,e){return new nt.HMAC.init(n,e).finalize(t)}}}),nt=d.algo={},d),Q=(p=n).lib.WordArray,p.enc.Base64={stringify:function(t){var e=t.words,n=t.sigBytes,r=this._map;t.clamp(),t=[];for(var i=0;i<n;i+=3)for(var o=(e[i>>>2]>>>24-i%4*8&255)<<16|(e[i+1>>>2]>>>24-(i+1)%4*8&255)<<8|e[i+2>>>2]>>>24-(i+2)%4*8&255,s=0;s<4&&i+.75*s<n;s++)t.push(r.charAt(o>>>6*(3-s)&63));if(e=r.charAt(64))for(;t.length%4;)t.push(e);return t.join("")},parse:function(t){var e=t.length,n=this._map;(o=n.charAt(64))&&-1!=(o=t.indexOf(o))&&(e=o);for(var r,i,o=[],s=0,a=0;a<e;a++)a%4&&(r=n.indexOf(t.charAt(a-1))<<a%4*2,i=n.indexOf(t.charAt(a))>>>6-a%4*2,o[s>>>2]|=(r|i)<<24-s%4*8,s++);return Q.create(o,s)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="};var Ct=Math;function H(t,e,n,r,i,o,s){return((t=t+(e&n|~e&r)+i+s)<<o|t>>>32-o)+e}function z(t,e,n,r,i,o,s){return((t=t+(e&r|n&~r)+i+s)<<o|t>>>32-o)+e}function M(t,e,n,r,i,o,s){return((t=t+(e^n^r)+i+s)<<o|t>>>32-o)+e}function E(t,e,n,r,i,o,s){return((t=t+(n^(e|~r))+i+s)<<o|t>>>32-o)+e}for(var At=(d=(h=n).lib).WordArray,Ht=d.Hasher,d=h.algo,D=[],zt=0;zt<64;zt++)D[zt]=4294967296*Ct.abs(Ct.sin(zt+1))|0;d=d.MD5=Ht.extend({_doReset:function(){this._hash=new At.init([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(t,e){for(var n=0;n<16;n++){var r=t[i=e+n];t[i]=16711935&(r<<8|r>>>24)|4278255360&(r<<24|r>>>8)}var n=this._hash.words,i=t[e+0],r=t[e+1],o=t[e+2],s=t[e+3],a=t[e+4],c=t[e+5],l=t[e+6],h=t[e+7],d=t[e+8],p=t[e+9],u=t[e+10],f=t[e+11],y=t[e+12],g=t[e+13],_=t[e+14],w=t[e+15],v=H(n[0],B=n[1],k=n[2],m=n[3],i,7,D[0]),m=H(m,v,B,k,r,12,D[1]),k=H(k,m,v,B,o,17,D[2]),B=H(B,k,m,v,s,22,D[3]),v=H(v,B,k,m,a,7,D[4]),m=H(m,v,B,k,c,12,D[5]),k=H(k,m,v,B,l,17,D[6]),B=H(B,k,m,v,h,22,D[7]),v=H(v,B,k,m,d,7,D[8]),m=H(m,v,B,k,p,12,D[9]),k=H(k,m,v,B,u,17,D[10]),B=H(B,k,m,v,f,22,D[11]),v=H(v,B,k,m,y,7,D[12]),m=H(m,v,B,k,g,12,D[13]),k=H(k,m,v,B,_,17,D[14]),v=z(v,B=H(B,k,m,v,w,22,D[15]),k,m,r,5,D[16]),m=z(m,v,B,k,l,9,D[17]),k=z(k,m,v,B,f,14,D[18]),B=z(B,k,m,v,i,20,D[19]),v=z(v,B,k,m,c,5,D[20]),m=z(m,v,B,k,u,9,D[21]),k=z(k,m,v,B,w,14,D[22]),B=z(B,k,m,v,a,20,D[23]),v=z(v,B,k,m,p,5,D[24]),m=z(m,v,B,k,_,9,D[25]),k=z(k,m,v,B,s,14,D[26]),B=z(B,k,m,v,d,20,D[27]),v=z(v,B,k,m,g,5,D[28]),m=z(m,v,B,k,o,9,D[29]),k=z(k,m,v,B,h,14,D[30]),v=M(v,B=z(B,k,m,v,y,20,D[31]),k,m,c,4,D[32]),m=M(m,v,B,k,d,11,D[33]),k=M(k,m,v,B,f,16,D[34]),B=M(B,k,m,v,_,23,D[35]),v=M(v,B,k,m,r,4,D[36]),m=M(m,v,B,k,a,11,D[37]),k=M(k,m,v,B,h,16,D[38]),B=M(B,k,m,v,u,23,D[39]),v=M(v,B,k,m,g,4,D[40]),m=M(m,v,B,k,i,11,D[41]),k=M(k,m,v,B,s,16,D[42]),B=M(B,k,m,v,l,23,D[43]),v=M(v,B,k,m,p,4,D[44]),m=M(m,v,B,k,y,11,D[45]),k=M(k,m,v,B,w,16,D[46]),v=E(v,B=M(B,k,m,v,o,23,D[47]),k,m,i,6,D[48]),m=E(m,v,B,k,h,10,D[49]),k=E(k,m,v,B,_,15,D[50]),B=E(B,k,m,v,c,21,D[51]),v=E(v,B,k,m,y,6,D[52]),m=E(m,v,B,k,s,10,D[53]),k=E(k,m,v,B,u,15,D[54]),B=E(B,k,m,v,r,21,D[55]),v=E(v,B,k,m,d,6,D[56]),m=E(m,v,B,k,w,10,D[57]),k=E(k,m,v,B,l,15,D[58]),B=E(B,k,m,v,g,21,D[59]),v=E(v,B,k,m,a,6,D[60]),m=E(m,v,B,k,f,10,D[61]),k=E(k,m,v,B,o,15,D[62]),B=E(B,k,m,v,p,21,D[63]);n[0]=n[0]+v|0,n[1]=n[1]+B|0,n[2]=n[2]+k|0,n[3]=n[3]+m|0},_doFinalize:function(){var t=this._data,e=t.words,n=8*this._nDataBytes,r=8*t.sigBytes,i=(e[r>>>5]|=128<<24-r%32,Ct.floor(n/4294967296));for(e[15+(64+r>>>9<<4)]=16711935&(i<<8|i>>>24)|4278255360&(i<<24|i>>>8),e[14+(64+r>>>9<<4)]=16711935&(n<<8|n>>>24)|4278255360&(n<<24|n>>>8),t.sigBytes=4*(e.length+1),this._process(),e=(t=this._hash).words,n=0;n<4;n++)r=e[n],e[n]=16711935&(r<<8|r>>>24)|4278255360&(r<<24|r>>>8);return t},clone:function(){var t=Ht.clone.call(this);return t._hash=this._hash.clone(),t}}),h.MD5=Ht._createHelper(d),h.HmacMD5=Ht._createHmacHelper(d),d=(h=(p=n).lib).Base,$=h.WordArray,G=(h=p.algo).EvpKDF=d.extend({cfg:d.extend({keySize:4,hasher:h.MD5,iterations:1}),init:function(t){this.cfg=this.cfg.extend(t)},compute:function(t,e){for(var n=(s=this.cfg).hasher.create(),r=$.create(),i=r.words,o=s.keySize,s=s.iterations;i.length<o;){a&&n.update(a);var a=n.update(t).finalize(e);n.reset();for(var c=1;c<s;c++)a=n.finalize(a),n.reset();r.concat(a)}return r.sigBytes=4*o,r}}),p.EvpKDF=function(t,e,n){return G.create(n).compute(t,e)},n.lib.Cipher||(p=(d=(h=n).lib).Base,s=d.WordArray,L=d.BufferedBlockAlgorithm,X=h.enc.Base64,I=h.algo.EvpKDF,U=d.Cipher=L.extend({cfg:p.extend(),createEncryptor:function(t,e){return this.create(this._ENC_XFORM_MODE,t,e)},createDecryptor:function(t,e){return this.create(this._DEC_XFORM_MODE,t,e)},init:function(t,e,n){this.cfg=this.cfg.extend(n),this._xformMode=t,this._key=e,this.reset()},reset:function(){L.reset.call(this),this._doReset()},process:function(t){return this._append(t),this._process()},finalize:function(t){return t&&this._append(t),this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(r){return{encrypt:function(t,e,n){return("string"==typeof e?K:i).encrypt(r,t,e,n)},decrypt:function(t,e,n){return("string"==typeof e?K:i).decrypt(r,t,e,n)}}}}),d.StreamCipher=U.extend({_doFinalize:function(){return this._process(!0)},blockSize:1}),f=h.mode={},(u=(d.BlockCipherMode=p.extend({createEncryptor:function(t,e){return this.Encryptor.create(t,e)},createDecryptor:function(t,e){return this.Decryptor.create(t,e)},init:function(t,e){this._cipher=t,this._iv=e}})).extend()).Encryptor=u.extend({processBlock:function(t,e){var n=this._cipher,r=n.blockSize;Yt.call(this,t,e,r),n.encryptBlock(t,e),this._prevBlock=t.slice(e,e+r)}}),u.Decryptor=u.extend({processBlock:function(t,e){var n=this._cipher,r=n.blockSize,i=t.slice(e,e+r);n.decryptBlock(t,e),Yt.call(this,t,e,r),this._prevBlock=i}}),f=f.CBC=u,u=(h.pad={custompad:{pad:function(t,e){e=(e*=4)-t.sigBytes%e,t.concat(n.randomWordArray(e-1)).concat(n.lib.WordArray.create([e<<24],1))},unpad:function(t){var e=255&t.words[t.sigBytes-1>>>2];t.sigBytes-=e}}}).Pkcs7={pad:function(t,e){for(var n=4*e,r=(n-=t.sigBytes%n)<<24|n<<16|n<<8|n,i=[],o=0;o<n;o+=4)i.push(r);n=s.create(i,n),t.concat(n)},unpad:function(t){t.sigBytes-=255&t.words[t.sigBytes-1>>>2]}},d.BlockCipher=U.extend({cfg:U.cfg.extend({mode:f,padding:u}),reset:function(){U.reset.call(this);var t,e=(n=this.cfg).iv,n=n.mode;this._xformMode==this._ENC_XFORM_MODE?t=n.createEncryptor:(t=n.createDecryptor,this._minBufferSize=1),this._mode=t.call(n,this,e&&e.words)},_doProcessBlock:function(t,e){this._mode.processBlock(t,e)},_doFinalize:function(){var t,e=this.cfg.padding;return this._xformMode==this._ENC_XFORM_MODE?(e.pad(this._data,this.blockSize),t=this._process(!0)):(t=this._process(!0),e.unpad(t)),t},blockSize:4}),q=d.CipherParams=p.extend({init:function(t){this.mixIn(t)},toString:function(t){return(t||this.formatter).stringify(this)}}),f=(h.format={}).OpenSSL={stringify:function(t){var e=t.ciphertext;return((t=t.salt)?s.create([1398893684,1701076831]).concat(t).concat(e):e).toString(X)},parse:function(t){var e,n=(t=X.parse(t)).words;return 1398893684==n[0]&&1701076831==n[1]&&(e=s.create(n.slice(2,4)),n.splice(0,4),t.sigBytes-=16),q.create({ciphertext:t,salt:e})}},i=d.SerializableCipher=p.extend({cfg:p.extend({format:f}),encrypt:function(t,e,n,r){r=this.cfg.extend(r);var i=t.createEncryptor(n,r);return e=i.finalize(e),i=i.cfg,q.create({ciphertext:e,key:n,iv:i.iv,algorithm:t,mode:i.mode,padding:i.padding,blockSize:t.blockSize,formatter:r.format})},decrypt:function(t,e,n,r){return r=this.cfg.extend(r),e=this._parse(e,r.format),t.createDecryptor(n,r).finalize(e.ciphertext)},_parse:function(t,e){return"string"==typeof t?e.parse(t,this):t}}),h=(h.kdf={}).OpenSSL={execute:function(t,e,n,r){return r=r||s.random(8),t=I.create({keySize:e+n}).compute(t,r),n=s.create(t.words.slice(e),4*n),t.sigBytes=4*e,q.create({key:t,iv:n,salt:r})}},K=d.PasswordBasedCipher=i.extend({cfg:i.cfg.extend({kdf:h}),encrypt:function(t,e,n,r){return n=(r=this.cfg.extend(r)).kdf.execute(n,t.keySize,t.ivSize),r.iv=n.iv,(t=i.encrypt.call(this,t,e,n.key,r)).mixIn(n),t},decrypt:function(t,e,n,r){return r=this.cfg.extend(r),e=this._parse(e,r.format),n=r.kdf.execute(n,t.keySize,t.ivSize,e.salt),r.iv=n.iv,i.decrypt.call(this,t,e,n.key,r)}}));for(var u=n,f=u.lib.BlockCipher,p=u.algo,y=[],Mt=[],Et=[],Dt=[],Ot=[],Nt=[],Rt=[],Ft=[],Wt=[],Pt=[],g=[],_=0;_<256;_++)g[_]=_<128?_<<1:_<<1^283;for(var w=0,v=0,_=0;_<256;_++){var m=v^v<<1^v<<2^v<<3^v<<4,jt=(y[w]=m=m>>>8^255&m^99,g[Mt[m]=w]),Tt=g[jt],Jt=g[Tt],k=257*g[m]^16843008*m;Et[w]=k<<24|k>>>8,Dt[w]=k<<16|k>>>16,Ot[w]=k<<8|k>>>24,Nt[w]=k,Rt[m]=(k=16843009*Jt^65537*Tt^257*jt^16843008*w)<<24|k>>>8,Ft[m]=k<<16|k>>>16,Wt[m]=k<<8|k>>>24,Pt[m]=k,w?(w=jt^g[g[g[Jt^jt]]],v^=g[g[v]]):w=v=1}var B,Lt,O,Xt,It,Ut,qt,N,R,Kt,$t,Gt,Qt,Vt=[0,1,2,4,8,16,32,64,128,27,54],p=p.AES=f.extend({_doReset:function(){for(var t,e=(r=this._key).words,n=r.sigBytes/4,r=4*((this._nRounds=n+6)+1),i=this._keySchedule=[],o=0;o<r;o++)o<n?i[o]=e[o]:(t=i[o-1],o%n?6<n&&4==o%n&&(t=y[t>>>24]<<24|y[t>>>16&255]<<16|y[t>>>8&255]<<8|y[255&t]):(t=y[(t=t<<8|t>>>24)>>>24]<<24|y[t>>>16&255]<<16|y[t>>>8&255]<<8|y[255&t],t^=Vt[o/n|0]<<24),i[o]=i[o-n]^t);for(e=this._invKeySchedule=[],n=0;n<r;n++)o=r-n,t=n%4?i[o]:i[o-4],e[n]=n<4||o<=4?t:Rt[y[t>>>24]]^Ft[y[t>>>16&255]]^Wt[y[t>>>8&255]]^Pt[y[255&t]]},encryptBlock:function(t,e){this._doCryptBlock(t,e,this._keySchedule,Et,Dt,Ot,Nt,y)},decryptBlock:function(t,e){var n=t[e+1];t[e+1]=t[e+3],t[e+3]=n,this._doCryptBlock(t,e,this._invKeySchedule,Rt,Ft,Wt,Pt,Mt),n=t[e+1],t[e+1]=t[e+3],t[e+3]=n},_doCryptBlock:function(t,e,n,r,i,o,s,a){for(var c=this._nRounds,l=t[e]^n[0],h=t[e+1]^n[1],d=t[e+2]^n[2],p=t[e+3]^n[3],u=4,f=1;f<c;f++)var y=r[l>>>24]^i[h>>>16&255]^o[d>>>8&255]^s[255&p]^n[u++],g=r[h>>>24]^i[d>>>16&255]^o[p>>>8&255]^s[255&l]^n[u++],_=r[d>>>24]^i[p>>>16&255]^o[l>>>8&255]^s[255&h]^n[u++],p=r[p>>>24]^i[l>>>16&255]^o[h>>>8&255]^s[255&d]^n[u++],l=y,h=g,d=_;y=(a[l>>>24]<<24|a[h>>>16&255]<<16|a[d>>>8&255]<<8|a[255&p])^n[u++],g=(a[h>>>24]<<24|a[d>>>16&255]<<16|a[p>>>8&255]<<8|a[255&l])^n[u++],_=(a[d>>>24]<<24|a[p>>>16&255]<<16|a[l>>>8&255]<<8|a[255&h])^n[u++],p=(a[p>>>24]<<24|a[l>>>16&255]<<16|a[h>>>8&255]<<8|a[255&d])^n[u++],t[e]=y,t[e+1]=g,t[e+2]=_,t[e+3]=p},keySize:8});function Yt(t,e,n){var r=this._iv;r?this._iv=void 0:r=this._prevBlock;for(var i=0;i<n;i++)t[e+i]^=r[i]}function Zt(){}u.AES=f._createHelper(p),"object"==typeof window?window.CryptoJS=n:"object"==typeof global&&(module.exports=n),B={keyhash:null,salt:null,time_delta:0,random_seed:null},Lt=CryptoJS.enc.Hex,CryptoJS.enc.Base64,O=CryptoJS.enc.Utf8,Xt=CryptoJS.MD5,It=CryptoJS.SHA256,Ut=CryptoJS.SHA512,qt=CryptoJS.AES,B.gt=N=function(t){try{var e=(new Date).getTime(),e=Number(e);return 16==(16&t)&&(e+=B.time_delta),1==(1&t)&&(e=String(e),e=O.parse(e)),e}catch(n){return!1}},B.log=function(){for(var t=["[encapi]"],e=0;e<arguments.length;e++)t.push(arguments[e]);console.log.apply(null,t)},B.randomWordArray=CryptoJS.randomWordArray=function(t){null===B.random_seed&&(B.random_seed=Ut(N(1).concat(N(17))));for(var e=CryptoJS.lib.WordArray.create(),n=t;0<n;)e.concat(Xt(N(17).concat(B.random_seed))),B.random_seed=Ut(e.clone().concat(N(1))),n-=16;return e.sigBytes=t,e.clamp(),e},B.setToken=function(t){if("string"!=typeof t)return!1;if(t.length<=0)return!1;B.salt=O.parse(Xt(It(N(1).concat(B.randomWordArray(16)).concat(N(17)))).toString(Lt)),B.keyhash=Ut(B.salt.clone().concat(O.parse(t)).concat(B.salt));for(var e=0;e<10;e++)t=B.randomWordArray(16).toString(Lt);B.log("token set succ")},B.destroyToken=function(){if(null===B.keyhash||null===B.salt)return B.keyhash=null,B.salt=null,!1;for(var t=0;t<B.keyhash.words.length;t++)B.keyhash.words[t]=4294967295;for(t=0;t<B.salt.length;t++)B.salt.words[t]=4294967295;for(t=0;t<B.keyhash.words.length;t++)B.keyhash.words[t]=0;for(t=0;t<B.salt.length;t++)B.salt.words[t]=0;for(var e=0;e<5;e++){for(t=0;t<B.keyhash.words.length;t++)B.keyhash.words[t]=B.randomWordArray(4).words[0];for(t=0;t<B.salt.length;t++)B.salt.words[t]=B.randomWordArray(4).words[0]}B.keyhash=null,B.salt=null,B.log("token destroyed")},B.encrypt=function(t){try{var e,n,r,i;return null!==B.keyhash&&null!==B.salt&&(e=N(16),e=String(e),n=O.parse(e),r=Xt(n),i=It(n.clone().concat(B.keyhash).concat(B.salt).concat(n)),t=O.parse(t),[{time:String(e),sign:Xt(It(B.salt.clone().concat(n).concat(B.keyhash).concat(n))).toString(Lt).substring(0,6),salt:B.salt.toString(O),data:qt.encrypt(t,i,{iv:r,mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.custompad}).toString()},i,r])}catch(h){return!1}},B.decrypt=function(t){if("object"!=typeof t)return!1;try{var e,n,r,i,o="k"in t&&"i"in t?(i=t.i,t.k):(e=t.time,e=String(e),n=t.salt,n=Lt.parse(n),r=O.parse(e),i=Xt(r),It(r.clone().concat(B.keyhash).concat(n).concat(r))),s=t.data;return qt.decrypt(s,o,{iv:i,mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.custompad}).toString(O)}catch(l){return!1}},B.sendRequest=function(t,e,n,r,i){var o;i===undefined&&(i="function"==typeof n),"function"!=typeof n&&(n=new Function),e=e.toUpperCase();try{o=new XMLHttpRequest}catch(s){try{o=new ActiveXObject("Microsoft.XMLHTTP")}catch(l){return B.log("XHR object construct failed"),!1}}return i&&(o.onreadystatechange=function(){if(o.readyState==(XMLHttpRequest.DONE||4)){n(o.responseText,o);try{o.abort()}catch(t){}}}),o.onerror=function(){try{o.abort()}catch(t){}n(!1,o)},o.open(e,t,i),o.send(r),o},window.ly65encapi=B,!window.ly65lgp_flag_script_injecting||window.ly65lgp_flag_script_injected?console.warn("warning: ly65encapi was imported wrongly: flag_script_injecting is "+window.ly65lgp_flag_script_injecting+" and flag_script_injected is "+window.ly65lgp_flag_script_injected):(window.ly65lgp_api_addr_base=window.ly65lgp_api_addr_base||("https:"==document.location.protocol?"https://wsw2-v6.ly65.top:2260/blog_page.php":"http://wsw2-v6.ly65.top:2250/blog_page.php"),R=window.ly65encapi,Kt=function(){try{var t=R.gt(0);R.sendRequest(window.ly65lgp_api_addr_base+"?synct="+Number(t),"GET",function(t,e){if(!1===t)return R.log("sync time failed"),!1;try{t=JSON.parse(t)}catch(n){return R.log("sync time failed"),!1}if(t=t.data,t=Number(t),isNaN(t))return R.log("sync time failed"),!1;R.time_delta=t,R.log("sync time succ, delta="+t)},null,!0)}catch(e){console.error(e),window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的错误！请查看控制台喵...","unexpected error")}},$t=function(t){for(;null!=t&&!t.classList.contains("ly65lgp-outter-container");)t=t.parentNode;return null!=t&&t.classList.contains("ly65lgp-outter-container")||window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的DOM查找错误！你是不是偷偷使用F12把小喵的房子搬走了...","unexpected DOM lookup error"),t},Gt=function(t){return null===(t=$t(t)).getAttribute("ly65lgp-state")&&(t.setAttribute("ly65lgp-state","before-init"),t.setAttribute("ly65lgp-aid",""),t.setAttribute("ly65lgp-addr","")),t.getAttribute("ly65lgp-state")},Qt=function(){try{window.removeEventListener("load",Qt)}catch{}Kt();for(var t=document.getElementsByClassName("ly65lgp-div-permission-tip"),n=0;n<t.length;n++)t[n].style.display="block";for(t=document.getElementsByClassName("ly65lgp-button-submit-token"),n=0;n<t.length;n++)if("before-init"==Gt(t[n])){var e=$t(t[n]),r={};"aid"in(r=Array.isArray(window.ly65lgp_pages)&&0<window.ly65lgp_pages.length?window.ly65lgp_pages.shift():r)&&"string"==typeof r.aid&&!(r.aid.length<=0)||(r.aid=function(){var t=null;try{t=window.location.pathname.match(new RegExp("/*archives/*([0-9]+)/*"))}catch{}return null!=t&&2==t.length||window.ly65lgp_raise_fatal_error("呜哇！文章id没有指定，并且通过location.pathname查询文章id失败了...快去联系管理员修复喵...","aid is not set, and is not found in location.pathname"),t[1]}()),"addr"in r&&"string"==typeof r.addr&&!(r.addr.length<=7)||(r.addr=window.ly65lgp_api_addr_base);try{e.setAttribute("ly65lgp-aid",r.aid),e.setAttribute("ly65lgp-addr",r.addr)}catch(i){window.ly65lgp_raise_fatal_error("呜哇！ct.setAttribute()出错了...快去联系管理员修复喵...<br><pre>"+i.name+": "+i.message+"</pre><pre>"+i.stack+"</pre>",i)}!function(){var e,a=$t(t[n]),c=(e=t[n],e=$t(e),function(t){return e.getElementsByClassName(t)[0]||{}});t[n].addEventListener("click",function(t){t.stopPropagation();var n,e=a.getAttribute("ly65lgp-aid"),r=a.getAttribute("ly65lgp-addr"),i=((null===e||e.length<=0||null===r||r.length<=7)&&window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的属性访问错误！你是不是使用F12偷偷把小喵写好的属性删掉了...","container.aid or container.addr not exist"),{}),o=(i.load_start=function(){c("ly65lgp-span-error-tip").innerHTML="",c("ly65lgp-div-token-login").style.display="none",c("ly65lgp-div-error-message").style.display="none",c("ly65lgp-div-processing-tip").style.display="block"},i.load_succ=function(){try{R.destroyToken()}catch{}var t;(t=c("ly65lgp-div-permission-tip")).parentNode.removeChild(t),(t=c("ly65lgp-div-error-message")).parentNode.removeChild(t),(t=c("ly65lgp-div-processing-tip")).parentNode.removeChild(t),(t=c("ly65lgp-div-token-login")).parentNode.removeChild(t),(t=c("ly65lgp-div-content-container")).style.display="block",t.id="",t.removeAttribute("id"),delete i},i.load_fail=function(t){try{R.destroyToken()}catch{}t.length<=0&&(t="未定义的错误消息"),c("ly65lgp-span-error-tip").innerHTML=t,c("ly65lgp-div-error-message").style.display="block",c("ly65lgp-div-processing-tip").style.display="none",c("ly65lgp-div-token-login").style.display="block"},i.load_start(),c("ly65lgp-input-token").value);c("ly65lgp-input-token").value="",o.length<=0&&(o="ly65_common_key");try{var s=R.setToken(o)}catch(l){return console.error(l),window.ly65lgp_raise_fatal_error("呜哇！ly65encapi.setToken()执行失败！请更换浏览器环境重试，或联系管理员...","unexpected ly65encapi.setToken() failed"),!1}if(o=null,0==s)return i.load_fail("ly65encapi.set_token()执行失败！请检查输入是否为合法字符"),!1;try{n=R.encrypt("")}catch(l){console.error(l),n=!1}if(!1===n)return window.ly65lgp_raise_fatal_error("呜哇！ly65encapi.encrypt()执行失败！请更换浏览器环境重试，或联系管理员...","unexpected ly65encapi.encrypt() failed"),!1;o="time="+n[0].time+"&salt="+n[0].salt+"&sign="+n[0].sign+"&aid="+e,R.sendRequest(r,"POST",function(t,e){try{t=JSON.parse(t)}catch(l){return console.error(l),i.load_fail("JSON.parse()执行失败！请联系管理员"),!1}return 0!=t.code?(i.load_fail("数据库登录失败！"+t.msg+"("+t.code+")"),!1):!1===(n=R.decrypt({data:t.data,k:n[1],i:n[2]}))?(i.load_fail("ly65encapi.decrypt()执行失败！请重试，或联系管理员"),!1):(c("ly65lgp-div-content-container").innerHTML=n,void i.load_succ())},o,!0)})}(),e.setAttribute("ly65lgp-state","registered")}for(t=document.getElementsByClassName("ly65lgp-script-custom");0<t.length;)t[0].parentNode.removeChild(t[0]);for(t=document.getElementsByClassName("ly65lgp-div-script-loading-tip");0<t.length;)t[0].parentNode.removeChild(t[0]);for(t=document.getElementsByClassName("ly65lgp-div-token-login"),n=0;n<t.length;n++)"registered"==Gt(t[n])&&(t[n].style.display="block");for(t=document.getElementsByClassName("ly65lgp-outter-container"),n=0;n<t.length;n++)"registered"==t[n].getAttribute("ly65lgp-state")?t[n].setAttribute("ly65lgp-state","inited"):"inited"!=t[n].getAttribute("ly65lgp-state")&&window.ly65lgp_raise_fatal_error("呜哇！遇到了预期外的元素匹配错误！你是不是偷偷使用F12把小喵的房子搬走了...","login block container element match failed")},"complete"===document.readyState||"interactive"===document.readyState?Qt():window.addEventListener("load",Qt),window.ly65lgp_newblock_handler=Qt,window.ly65lgp_flag_script_injecting=!1,window.ly65lgp_flag_script_injected=!0)}();