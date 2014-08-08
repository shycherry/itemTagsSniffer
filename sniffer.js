var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;
var Async = require('async');
var Path = require('path');

var Sniffer = module.exports = function (options) {

  if(!(this instanceof Sniffer))
    return new Sniffer(options);

  var _itDB;
  var _configDB;
  var _requestQueue;
  var _ready;
  
  if ('undefined' != typeof options) this.configure(options);
};

inherits(Sniffer, EventEmitter);

/**
* exposed API
*/
Sniffer.prototype.configure = configure;
Sniffer.prototype.doSniff = function(iCallback){return this._requestQueue.push(doSniff.bind(this), iCallback)};
Sniffer.prototype.getDB = function(iCallback){return this._requestQueue.push(getDB.bind(this), iCallback)};

/**
* methods
*/
function configure(options){
  var self = this;
  
  this._requestQueue = Async.queue(function(iRequestTask, iCallback){
    if(self._ready){
      iRequestTask(iCallback);  
    }else{
      self.once('ready', function(){
        iRequestTask(iCallback)
      });
    }    
  }, 1);

  this._ready = false;
  this.once('ready', function(){
    self._ready = true;
  });

  if('undefined' != typeof options.configDB){
    this._configDB = require('itemTagsDB')({database: options.configDB});
    this._configDB.fetchItemsSharingTags(['snifferConfig'], function(err, items){
      if(!err && items && items.length == 1){
        var snifferConfig = items[0].getTagValue('snifferConfig');
        if(snifferConfig && snifferConfig.database){
          self._itDB = require('itemTagsDB')({database: snifferConfig.database});
          self.emit('ready');
        }else{
          self.emit('error');
        }
      }else{
        self.emit('error');
      }
    });
  }
}

function getDB(iCallback){
  if(iCallback) iCallback(null, this._itDB);
}

function doSniff(iCallback){
  var self = this;
  if(!this._configDB){
    iCallback('no configDB');
  }

  self._itDB.deleteAll(function(err){
    if(err){
      if(iCallback) iCallback(err);
    }else{
      self._configDB.fetchItemsSharingTags(['sniffPath'], function(err, items){
        if(!err){
          var sniffingQueue = Async.queue(_handleSniffPath_.bind(self), 1);
          sniffingQueue.empty = function(){console.log('sniffingQueue is empty');};
          sniffingQueue.drain = function(){console.log('sniffingQueue is drained');};
          sniffingQueue.saturated = function(){console.log('sniffingQueue is saturated');};

          var sniffPathReportsProcessed = 0;

          var testIfLastCallback = function (err){
            if((sniffPathReportsProcessed == items.length))
            {
              if(iCallback) iCallback(err);
            }
          };

          for(var sniffPathIdx = 0; sniffPathIdx<items.length; sniffPathIdx++){
                    
            var watchTask = {
              "sniffPath": items[sniffPathIdx],
              "configDB": self._configDB
            };

            sniffingQueue.push(watchTask, function(err, iSniffReport){
              
              if(!err){
                console.log(iSniffReport);
                _handleWatchReport_(iSniffReport, self._itDB, function(err){
                  sniffPathReportsProcessed ++;
                  testIfLastCallback(err);
                });
              }else{
                console.log(err);
                sniffPathReportsProcessed ++;
                testIfLastCallback(err);
              }

            });
          }
        
        }
      });
    }
  })

  
}

function _handleSniffPath_(iSniffTask, iCallback){

  var sniffPath = iSniffTask['sniffPath'];
  var configDB = iSniffTask['configDB'];

  if(sniffPath.xorHasTags(['ftpSniffPath'])){
    
    configDB.fetchOne(sniffPath.getTagValue('ftpSniffPath').ftpConfig, (function(iSniffPath){
      return function(err, itemFtpConfig){
        if(!err){
          _handleFtpPaths_(
            itemFtpConfig.getTagValue('ftpConfig'), 
            iSniffPath.getTagValue('ftpSniffPath').path,
            iSniffPath.getTagValue('sniffPath').tagWith, 
            function(err, report){
              iCallback(err, report);
            }
          );
        }
      };
    })(sniffPath));
  
  }else if(sniffPath.xorHasTags(['dummySniffPath'])){
    
    _handleDummyPaths_(sniffPath, function(err, report){
      iCallback(err, report);
    });

  }else if(sniffPath.xorHasTags(['dummySniffPath2'])){
    
    _handleDummyPaths2_(sniffPath, function(err, report){
      iCallback(err, report);
    });

  }
}

function _handleFtpPaths_(iFtpConfig, iPath, iTagWith, iCallback){
  var ftp = require('ftp')();
  var Url = require('url');
  var baseFtpUri = Url.format({
    protocol: 'ftp',
    hostname: iFtpConfig.host,
    auth: iFtpConfig.user+':'+iFtpConfig.password
  });
  baseFtpUri = Url.resolve(baseFtpUri, iPath);
  if(baseFtpUri[baseFtpUri.length-1] !== '/'){
    baseFtpUri+='/';
  }
  var report = {};

  ftp.on('ready', function(){
    ftp.list(iPath, function(err, list){
      for(var i in list){
        var fileOrDirName = (list[i].name)? list[i].name : '';
        report[i] = {
          'uri': Url.resolve(baseFtpUri, fileOrDirName),
          'tagWith': iTagWith
        };
      }
      ftp.end();
      iCallback(undefined, report);
    });
  });

  ftp.on('error', function(err){
    iCallback(err);
  });

  ftp.connect(iFtpConfig);
}

function _fileUriFilter_(iUri){
  return JSON.stringify({
    "@file" : {"uri" : iUri}
  });
}

function _handleWatchReport_(iSniffReport, iStoreDB, iCallback){
  if(!iStoreDB){
    if(iCallback)
      iCallback('no store db');
    return;
  }
  if(!iCallback)
    iCallback = function(){};

  var Entries = [];
  for(var iEntry in iSniffReport){
    Entries.push(iSniffReport[iEntry]);
  }

  //Here is items creation !
  function handleNextEntry(iCallback){
    var entry = Entries.shift();
    iStoreDB.fetchOneByFilter(_fileUriFilter_(entry.uri), (function(iEntry){
      return function(err, item){
        if(err){          
          item = iStoreDB.getNewItem(
          {
            "@file" : {
              "uri" : iEntry['uri']
            },
          });
        }
        
        item.addTags(iEntry['tagWith']);
        iStoreDB.save(item, function(err, item){
          if(iCallback)
            iCallback();
        });
        
      };
    })(entry));
  }

  Async.until( function(){return (Entries.length <= 0);}, handleNextEntry, iCallback);
}

function _handleDummyPaths_(iDummyWatchPath, iCallback){
  var watchReport = {
    0:{
      'uri':'ftp://bidule:truc@serveur.fr:21/path/to/heaven.avi',
      'tagWith':['dummyresult1','heaven','ftpFile'],
    },
    
    1:{
      'uri':'ftp://bidule:truc@serveur.fr:21/path/to/hell.avi',
      'tagWith':['dummyresult1','hell','ftpFile'],
    },

  };

  iCallback(undefined, watchReport);

}

function _handleDummyPaths2_(iDummyWatchPath, iCallback){
  var watchReport = {
    0:{
      'uri':'ftp://bidule:truc@serveur.fr:21/path/to/hell.avi',
      'tagWith':['dummyresult2','hell','ftpFile'],
    },

  };

  iCallback(undefined, watchReport);

}