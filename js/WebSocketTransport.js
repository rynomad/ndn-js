/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var WebSocketTransport = function WebSocketTransport() {    
	this.ws = null;
	this.maxBufferSize = 10000;  // Currently support 10000 bytes data input, consistent with BinaryXMLEncoder
	this.buffer = new Uint8Array(this.maxBufferSize);
	this.bufferOffset = 0;
	this.structureDecoder = new BinaryXMLStructureDecoder();
    this.defaultGetHostAndPort = NDN.makeShuffledGetHostAndPort
        (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu", 
          "E.ws.ndn.ucla.edu"],
         9696);
};

WebSocketTransport.prototype.connectWebSocket = function(ndn) {
	if (this.ws != null)
		delete this.ws;
	
	this.ws = new WebSocket('ws://' + ndn.host + ':' + ndn.port);
	if (LOG > 0) console.log('ws connection created.');
	
	this.ws.binaryType = "arraybuffer";
	
	var self = this;
	this.ws.onmessage = function(ev) {
		var result = ev.data;
		//console.log('RecvHandle called.');
			
		if(result == null || result == undefined || result == "" ) {
			console.log('INVALID ANSWER');
		} else if (result instanceof ArrayBuffer) {
	        var bytearray = new Uint8Array(result);
	        
			if (LOG>3) console.log('BINARY RESPONSE IS ' + DataUtils.toHex(bytearray));
			
			try {
				if (bytearray.length + self.bufferOffset >= self.buffer.byteLength) {
					if (LOG>3) {
						console.log("NDN.ws.onmessage: buffer overflow. Accumulate received length: " + self.bufferOffset 
							+ ". Current packet length: " + bytearray.length + ".");
					}
					
					// Purge and quit.
					delete self.structureDecoder;
					delete self.buffer;
					self.structureDecoder = new BinaryXMLStructureDecoder();
					self.buffer = new Uint8Array(self.maxBufferSize);
					self.bufferOffset = 0;
					return;
				}
				
				/*for (var i = 0; i < bytearray.length; i++) {
					self.buffer.push(bytearray[i]);
				}*/
				self.buffer.set(bytearray, self.bufferOffset);
				self.bufferOffset += bytearray.length;
				
				if (!self.structureDecoder.findElementEnd(self.buffer.subarray(0, self.bufferOffset))) {
					// Need more data to decode
					if (LOG>3) console.log('Incomplete packet received. Length ' + bytearray.length + '. Wait for more input.');
					return;
				}
				if (LOG>3) console.log('Complete packet received. Length ' + bytearray.length + '. Start decoding.');
			} catch (ex) {
				console.log("NDN.ws.onmessage exception: " + ex);
				return;
			}
			
            ndn.onReceivedElement(self.buffer);

			// Renew StrcutureDecoder and buffer after we process a full packet
			delete self.structureDecoder;
			delete self.buffer;
			self.structureDecoder = new BinaryXMLStructureDecoder();
			self.buffer = new Uint8Array(self.maxBufferSize);
			self.bufferOffset = 0;
		}
	}
	
	this.ws.onopen = function(ev) {
		if (LOG > 3) console.log(ev);
		if (LOG > 3) console.log('ws.onopen: WebSocket connection opened.');
		if (LOG > 3) console.log('ws.onopen: ReadyState: ' + this.readyState);

		// Fetch ccndid now
		var interest = new Interest(NDN.ccndIdFetcher);
		interest.interestLifetime = 4000; // milliseconds
        this.send(encodeToBinaryInterest(interest));
	}
	
	this.ws.onerror = function(ev) {
		console.log('ws.onerror: ReadyState: ' + this.readyState);
		console.log(ev);
		console.log('ws.onerror: WebSocket error: ' + ev.data);
	}
	
	this.ws.onclose = function(ev) {
		console.log('ws.onclose: WebSocket connection closed.');
		self.ws = null;
		
		// Close NDN when WebSocket is closed
		ndn.readyStatus = NDN.CLOSED;
		ndn.onclose();
		//console.log("NDN.onclose event fired.");
	}
};

/*
 * Send the Uint8Array data.
 */
WebSocketTransport.prototype.send = function(data) {
	if (this.ws != null) {
        // If we directly use data.buffer to feed ws.send(), 
        // WebSocket may end up sending a packet with 10000 bytes of data.
        // That is, WebSocket will flush the entire buffer
        // regardless of the offset of the Uint8Array. So we have to create
        // a new Uint8Array buffer with just the right size and copy the 
        // content from binaryInterest to the new buffer.
        //    ---Wentao
        var bytearray = new Uint8Array(data.length);
        bytearray.set(data);
        this.ws.send(bytearray.buffer);
		if (LOG > 3) console.log('ws.send() returned.');
	}
	else
		console.log('WebSocket connection is not established.');
}

WebSocketTransport.prototype.expressInterest = function(ndn, interest, closure) {
    if (ndn.readyStatus != NDN.OPENED) {
		console.log('Connection is not established.');
        return;
    }
    
	//TODO: check local content store first
	if (closure != null) {
		var pitEntry = new PITEntry(interest, closure);
        // TODO: This needs to be a single thread-safe transaction on a global object.
		NDN.PITTable.push(pitEntry);
		closure.pitEntry = pitEntry;
	}

	// Set interest timer
	if (closure != null) {
		pitEntry.timerID = setTimeout(function() {
			if (LOG > 3) console.log("Interest time out.");
				
			// Remove PIT entry from NDN.PITTable.
            // TODO: Make this a thread-safe operation on the global PITTable.
			var index = NDN.PITTable.indexOf(pitEntry);
			//console.log(NDN.PITTable);
			if (index >= 0) 
	            NDN.PITTable.splice(index, 1);
			//console.log(NDN.PITTable);
			//console.log(pitEntry.interest.name.getName());
				
			// Raise closure callback
			closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(ndn, interest, 0, null));
		}, interest.interestLifetime);  // interestLifetime is in milliseconds.
		//console.log(closure.timerID);
	}

	this.send(encodeToBinaryInterest(interest));
};

