(function(t){function e(e){for(var n,s,c=e[0],i=e[1],l=e[2],p=0,u=[];p<c.length;p++)s=c[p],Object.prototype.hasOwnProperty.call(r,s)&&r[s]&&u.push(r[s][0]),r[s]=0;for(n in i)Object.prototype.hasOwnProperty.call(i,n)&&(t[n]=i[n]);d&&d(e);while(u.length)u.shift()();return o.push.apply(o,l||[]),a()}function a(){for(var t,e=0;e<o.length;e++){for(var a=o[e],n=!0,c=1;c<a.length;c++){var i=a[c];0!==r[i]&&(n=!1)}n&&(o.splice(e--,1),t=s(s.s=a[0]))}return t}var n={},r={app:0},o=[];function s(e){if(n[e])return n[e].exports;var a=n[e]={i:e,l:!1,exports:{}};return t[e].call(a.exports,a,a.exports,s),a.l=!0,a.exports}s.m=t,s.c=n,s.d=function(t,e,a){s.o(t,e)||Object.defineProperty(t,e,{enumerable:!0,get:a})},s.r=function(t){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},s.t=function(t,e){if(1&e&&(t=s(t)),8&e)return t;if(4&e&&"object"===typeof t&&t&&t.__esModule)return t;var a=Object.create(null);if(s.r(a),Object.defineProperty(a,"default",{enumerable:!0,value:t}),2&e&&"string"!=typeof t)for(var n in t)s.d(a,n,function(e){return t[e]}.bind(null,n));return a},s.n=function(t){var e=t&&t.__esModule?function(){return t["default"]}:function(){return t};return s.d(e,"a",e),e},s.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},s.p="/";var c=window["webpackJsonp"]=window["webpackJsonp"]||[],i=c.push.bind(c);c.push=e,c=c.slice();for(var l=0;l<c.length;l++)e(c[l]);var d=i;o.push([0,"chunk-vendors"]),a()})({0:function(t,e,a){t.exports=a("56d7")},1:function(t,e){},2:function(t,e){},"56d7":function(t,e,a){"use strict";a.r(e);a("e260"),a("e6cf"),a("cca6"),a("a79d");var n=a("2b0e"),r=function(){var t=this,e=t.$createElement,a=t._self._c||e;return a("v-app",[a("v-app-bar",{attrs:{app:"",color:"primary",dark:""}},[a("v-spacer"),a("v-btn",{attrs:{href:"https://indico.dns-oarc.net/event/42/contributions/902/",target:"_blank",text:""}},[a("span",{staticClass:"mr-2"},[t._v("Talk at OARC 37")]),a("v-icon",[t._v("mdi-open-in-new")])],1),a("v-btn",{attrs:{href:"https://dnsviz.net/d/falcon.example.pq-dnssec.dedyn.io/dnssec/",target:"_blank",text:""}},[a("span",{staticClass:"mr-2"},[t._v("FALCON-512 Test Zone on DNSViz")]),a("v-icon",[t._v("mdi-open-in-new")])],1),a("v-btn",{attrs:{href:"https://github.com/nils-wisiol/dns-falcon/",target:"_blank",text:""}},[a("span",{staticClass:"mr-2"},[t._v("Code on GitHub")]),a("v-icon",[t._v("mdi-open-in-new")])],1)],1),a("v-main",[a("HelloWorld")],1)],1)},o=[],s=function(){var t=this,e=t.$createElement,a=t._self._c||e;return a("v-container",[a("v-row",{staticClass:"text-center"},[a("v-col",{staticClass:"mb-4 mt-4"},[a("h1",{staticClass:"display-2 font-weight-bold mb-3"},[t._v(" Post-Quantum DNSSEC with FALCON-512 and PowerDNS ")])])],1),a("v-row",[a("v-col",{staticClass:"mb-5",attrs:{cols:"12"}},[a("h2",{staticClass:"headline font-weight-bold mb-3"},[t._v(" Make a query to our resolver ")]),a("p",{staticClass:"subheading font-weight-regular"},[t._v(" Send queries to our post-quantum enabled verifying resolver! To obtain responses signed with FALCON-512, query "),a("code",[t._v("A")]),t._v(", "),a("code",[t._v("AAAA")]),t._v(", and "),a("code",[t._v("TXT")]),t._v(" records at "),a("code",[t._v("falcon.example.pq-dnssec.dedyn.io.")]),t._v(" and "),a("code",[t._v("*.falcon.example.pq-dnssec.dedyn.io.")]),t._v(". To get classical signatures, try "),a("code",[t._v("rsasha256.example.pq-dnssec.dedyn.io.")]),t._v(", "),a("code",[t._v("ecdsa256.example.pq-dnssec.dedyn.io.")]),t._v(", "),a("code",[t._v("ed25519.example.pq-dnssec.dedyn.io.")]),t._v(", and the like. ")]),a("p",{staticClass:"subheading font-weight-regular"},[t._v(" Queries will be sent from your browser using DNS-over-HTTPS to a PowerDNS recursor with FALCON-512 support. The recursor will query our PowerDNS authoritative DNS server (again, with FALCON-512 support), to get your reponse. The recursor will then validate the signature and send the result to your browser. All queries are send with the "),a("code",[t._v("DNSSEC_OK")]),t._v(" flag ("),a("code",[t._v("+dnssec")]),t._v(" in dig), so you will see "),a("code",[t._v("RRSIG")]),t._v(" and "),a("code",[t._v("NSEC")]),t._v("/"),a("code",[t._v("NSEC3")]),t._v(" records the the responses. ")]),a("p",[t._v(" For more information, please check out the code at "),a("a",{attrs:{href:"https://github.com/nils-wisiol/dns-falcon",target:"_blank"}},[t._v("GitHub")]),t._v(". ")])])],1),a("v-row",[a("v-col",[a("v-row",[a("v-text-field",{attrs:{filled:"",label:"Query type",type:"text"},model:{value:t.qtype,callback:function(e){t.qtype=e},expression:"qtype"}}),a("v-text-field",{attrs:{"append-outer-icon":"mdi-send",filled:"","clear-icon":"mdi-close-circle",clearable:"",label:"Enter a domain name",type:"text"},on:{"click:append-outer":t.query},model:{value:t.qname,callback:function(e){t.qname=e},expression:"qname"}})],1),t.working?a("v-row",[a("v-col",[a("div",{staticClass:"text-center"},[a("v-progress-circular",{attrs:{indeterminate:"",color:"primary"}})],1)])],1):t._e(),t.err?a("v-row",[a("v-alert",[t._v(t._s(t.err))])],1):t._e(),!t.working&&t.r_text?a("v-row",[a("code",{staticStyle:{overflow:"hidden"}},t._l(t.r_text,(function(e,n){return a("span",{key:n},[t._v(t._s(e)),a("br")])})),0)]):t._e()],1)],1)],1)},c=[],i=a("2909"),l=(a("99af"),a("a15b"),a("d3b7"),a("159b"),a("b0c0"),a("25f0"),a("131f")),d=a("929a"),p={name:"HelloWorld",data:function(){return{qtype:"TXT",qname:"falcon.example.pq-dnssec.dedyn.io",q:"",r_text:[],working:!1,err:!1}},methods:{query:function(){var t=this;this.working=!0,this.err=!1,this.q={type:"query",id:0,flags:d["RECURSION_DESIRED"],questions:[{type:this.qtype,name:this.qname}],additionals:[{type:"OPT",name:".",udpPayloadSize:4096,flags:32768}]},Object(l["sendDohMsg"])(this.q,"https://pq-dnssec.dedyn.io/dns-query","GET",[],1500).then((function(e){t.digest(e),t.working=!1})).catch((function(e){t.err=e,t.working=!1}))},digest:function(t){var e,a;this.r_text=[],this.r_text.push(";; ->>HEADER<<- opcode: ".concat(t.opcode,", status: ").concat(t.rcode,", id: ").concat(t.id));var n,r=[];(t.flag_qr&&r.push("qr"),t.flag_aa&&r.push("aa"),t.flag_tc&&r.push("tc"),t.flag_rd&&r.push("rd"),t.flag_ra&&r.push("ra"),t.flag_z&&r.push("z"),t.flag_ad&&r.push("ad"),t.flag_cd&&r.push("cd"),this.r_text.push(";; flags: ".concat(r.join(" "),"; QUERY: ").concat(t.questions.length,", ANSWER: ").concat(t.answers.length,", AUTHORITY: ").concat(t.authorities.length,", ADDITIONAL: ").concat(t.additionals.length)),this.r_text.push(""),this.r_text.push(";; QUESTION SECTION:"),(e=this.r_text).push.apply(e,Object(i["a"])(this.render_section(t.questions))),this.r_text.push(""),this.r_text.push(";; ANSWER SECTION:"),(a=this.r_text).push.apply(a,Object(i["a"])(this.render_section(t.answers))),this.r_text.push(""),t.authorities.length)&&(this.r_text.push(";; AUTHORITY SECTION:"),(n=this.r_text).push.apply(n,Object(i["a"])(this.render_section(t.authorities))),this.r_text.push(""))},render_section:function(t){var e=[];return t.forEach((function(t){var a="";t.data?(a="".concat(t.name," ").concat(t.ttl," ").concat(t.class," ").concat(t.type," "),"RRSIG"==t.type?a+="".concat(t.data.typeCovered," ").concat(t.data.algorithm," ").concat(t.data.labels," ").concat(t.data.originalTTL," ")+"".concat(t.data.inception," ").concat(t.data.expiration," ").concat(t.data.keyTag," ").concat(t.data.signersName," ")+"".concat(t.data.signature.toString("base64")):"TXT"==t.type?t.data.forEach((function(t){a+='"'.concat(t.toString(),'" ')})):"A"==t.type||"AAAA"==t.type?a+=t.data:"SOA"==t.type?a+="".concat(t.data.mname," ").concat(t.data.rname," ").concat(t.data.serial," ").concat(t.data.refresh," ").concat(t.data.retry," ").concat(t.data.expire," ").concat(t.data.minimum):"NSEC"==t.type||"NSEC3"==t.type?a+="".concat(t.data.nextDomain," ").concat(t.data.rrtypes.join(" ")):a=t):a="".concat(t.name," ").concat(t.class," ").concat(t.type),e.push(a)})),e}}},u=p,h=a("2877"),v=a("6544"),f=a.n(v),_=a("0798"),y=a("62ad"),g=a("a523"),m=a("490a"),b=a("0fd9"),w=a("8654"),x=Object(h["a"])(u,s,c,!1,null,null,null),S=x.exports;f()(x,{VAlert:_["a"],VCol:y["a"],VContainer:g["a"],VProgressCircular:m["a"],VRow:b["a"],VTextField:w["a"]});var q={name:"App",components:{HelloWorld:S},data:function(){return{}}},O=q,C=a("7496"),T=a("40dc"),A=a("8336"),N=a("132d"),E=a("f6c4"),k=a("2fa4"),j=Object(h["a"])(O,r,o,!1,null,null,null),D=j.exports;f()(j,{VApp:C["a"],VAppBar:T["a"],VBtn:A["a"],VIcon:N["a"],VMain:E["a"],VSpacer:k["a"]});var P=a("f309");n["a"].use(P["a"]);var R=new P["a"]({});n["a"].config.productionTip=!1,new n["a"]({vuetify:R,render:function(t){return t(D)}}).$mount("#app")}});
//# sourceMappingURL=app.a43244d5.js.map