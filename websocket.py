import time
import requests
import json

import websockets
import asyncio

UPBIT_WEB_SOCKET_ADD = 'wss://api.upbit.com/websocket/v1'
async def do_async_loop(trading_coins) :
    async with websockets.connect(UPBIT_WEB_SOCKET_ADD) as websocket:
        # ss format ex : '[{"ticket":"test1243563456"},{"type":"trade","codes":["KRW-BTC", "KRW-ETH"]}]'
        ss = '[{"ticket":"test1243563456"},{"type":"trade","codes":' + str(trading_coins).replace("'", '"') +'}]'
        await websocket.send(ss)
        cnt = 1
        while(1) :
            data_rev = await websocket.recv()
            my_json = data_rev.decode('utf8').replace("'", '"')
            data = json.loads(my_json)
            if len(data) > 0 :
                print(data['code'], data['trade_time'], data['ask_bid'], data['trade_price'], data['trade_volume'])
            if (cnt == 5) :  # adding the new coin, KRW-ETH after receiving 5 trs
                trading_coins.append('KRW-ETH')
                print('== adding KRW-ETH ==')
                ss = '[{"ticket":"test1243563456"},{"type":"trade","codes":' + str(trading_coins).replace("'", '"') +'}]'
                await websocket.send(ss)
            elif (cnt == 20) : # delete the last coin and adding the new coin, KRW-TRX after receiving 20 trs
                print('== deleting KRW-ETH ==')
                del trading_coins[-1]
                print('== adding KRW-TRX ==')
                trading_coins.append('KRW-TRX')
                ss = '[{"ticket":"test1243563456"},{"type":"trade","codes":' + str(trading_coins).replace("'", '"') +'}]'
                await websocket.send(ss)
            cnt += 1

def trading_main(trading_coins):
    asyncio.get_event_loop().run_until_complete(do_async_loop(trading_coins))

coins1 = [
        "KRW-BTC"
]

trading_main(coins1)
print('')