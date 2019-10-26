import sys
import frida

scr = """
Java.perform(function(){
		
		var Utils = Java.use('com.dodonew.online.util.Utils')
		Utils.md5.implementation = function(a){
			console.log('*'.repeat(30),'Hook md5 Start','*'.repeat(30))
			
			send('md5明文 => '+a);
			var result = this.md5(a);
			send('md5明文 => '+result);
			
			console.log('*'.repeat(30),'Hook md5 Success','*'.repeat(30))
			return result
		};

		var RequestUtil = Java.use('com.dodonew.online.http.RequestUtil')
		RequestUtil.encodeDesMap.overload('java.lang.String','java.lang.String','java.lang.String').implementation = function(data,key,iv){
			console.log('*'.repeat(30),'Hook encodeDesMap Start','*'.repeat(30))
			
			send('des明文 => '+data);
			send('desKey => '+key);
			send('desIv => '+iv);
			var result = this.encodeDesMap(data,key,iv);
			send('des密文 => '+result);
			
			console.log('*'.repeat(30),'Hook encodeDesMap Success','*'.repeat(30))
		return result
	};
});
"""


# 待调用的监控函数
def onMessage(message, data):
    '''
    处理返回结果 JS脚本会返回两个结果: message, data。也可以使用Frida -U -l example.js com.xxx.xxx
    :param message: JS返回的信息 JSON格式(JS对象) {'type': xxx, 'payload': xxx}
    :param data: 数据Nonde
    :return: None
    '''

    if message['type'] == 'send':
        print(f"[@]  {message['payload']}")
    else:
        print(message)


# 主函数 实现链接设备 监听等
def main():
    # 采用 remote 方式必须进行端口转发  或者使用get_usb_device()
    rdev = frida.get_usb_device()
    session = rdev.attach("com.dodonew.online")  # 目标应用包名 com.dodonew.online
    script = session.create_script(scr)
    script.on("message", onMessage)
    script.load()
    sys.stdin.read() # 维持终端会话


if __name__ == "__main__":
    main()
