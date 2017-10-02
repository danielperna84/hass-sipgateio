# hass-sipgateio
Use Sipgate.io to call Home Assistant services

This is a simple webserver that reacts on events published by Sipgate.io.
Can be used to call Home Assistant services via DTMF codes (see actions.py).

More info about Sibgate.io at:
https://www.sipgate.io
https://github.com/sipgate/sipgate.io

Still in early stage right now, not working with live sipgate.io (no onAnswer and onHangup events seem to be published). Only tested locally with curl:

Simulate new call:  
curl -X POST --data "event=newCall&from=4911223344&to=49987987&direction=in&callId=123456&user[]=Alice&user[]=Bob" http://localhost:3000

Simulate answering the call:  
curl -X POST --data "event=answer&callId=123456&user=John+Doe&from=4911223344&to=49987987&direction=in&answeringNumber=21199999999" http://localhost:3000

Simulate DTMF:  
curl -X POST --data "event=dtmf&dtmf=123456&callId=123456" http://localhost:3000

Simulate hangup:  
curl -X POST --data "event=hangup&cause=normalClearing&callId=123456&from=4911223344&to=49987987&direction=in&answeringNumber=4921199999999" http://localhost:3000
