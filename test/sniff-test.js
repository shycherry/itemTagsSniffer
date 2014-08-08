var fs = require('fs');
var async = require('async');

var S_OK = 'SUCCEEDED';
var E_FAIL = 'FAILED';
var CONFIG_DB_PATH = './sniff-test-snifferConfig.nosqltest';
var TMP_CONFIG_DB_PATH = './tmp-sniff-test-snifferConfig.nosql';
var DB_PORT = 1337;

var sniffer = null;
var TMP_DB_PATH =  './tmp-sniff-test-db.nosql';
var SWITCH_TMP_DB_PATH =  './last-tmp-sniff-test-db.nosql';

function loadDb(iCallback){
  sniffer = require('../sniffer')({
    configDB:TMP_CONFIG_DB_PATH
  });
  
  sniffer.on('ready', function(){
    iCallback(null, S_OK);
  });
}

function rmDB(){
  fs.unlinkSync(TMP_DB_PATH);
  fs.unlinkSync(TMP_CONFIG_DB_PATH);
}

console.log('start sniffer test');

function testSniff(iCallback){
  console.log('testSniff ');
  
  sniffer.doSniff(function(err){
    if(err){
      console.log('KO ',err);
      iCallback(err, E_FAIL);
    }else{
      iCallback(null, S_OK);
    }
  });
  
}

function testCheck(iCallback){
  console.log('testCheck ');
  sniffer.getDB(function(err, db){
    db.fetchAll(function(err, items){
      if(err){
        iCallback(err, E_FAIL);
      }else{
        if(items.length != 2){
          iCallback('bad expected count : got '+items.length+' expected 2', E_FAIL);
        }else{
          iCallback(null, S_OK);
        }
      }
    })
  });

}

async.series(
  {
    copyDb : function(callback){return copyFile(CONFIG_DB_PATH, TMP_CONFIG_DB_PATH, callback);},
    loadDb : function(callback){return loadDb(callback);},
    sniff: function(callback){return testSniff(callback);},
    check: function(callback){return testCheck(callback);}
  },

  function finishCallback(err, results){
    console.log('erreurs: '+JSON.stringify(err));
    console.log('test results:'+JSON.stringify(results));
    rmDB();
  }
);




//
//utilities 
//

function copyFile(source, target, cb) {
  //create a copy of db
  if(fs.existsSync(target)){
    fs.unlinkSync(target);
  }

  var cbCalled = false;

  var rd = fs.createReadStream(source);
  rd.on("error", function(err) {
    done(err);
  });
  var wr = fs.createWriteStream(target);
  wr.on("error", function(err) {
    done(err);
  });
  wr.on("close", function(ex) {
    done();
  });
  rd.pipe(wr);

  function done(err) {
    if (!cbCalled) {
      cb(err);
      cbCalled = true;
    }
  }
}
