<?php

namespace jcwxSdk;



/**
 * 中转服务器对象
 */
class Jcwx
{
    /**
     * 中转服务器地址(带http)
     * @var string
     */
    private string $url;
    /**
     * @var string 中转服务器-key
     */
    private string $key;
    /**
     * @var string 中转服务器-密码
     */
    private string $password;


    /**
     * @param string $url 中转服务器地址(带http)
     * @param string $key 中转服务器-key
     * @param string $password 中转服务器-密码
     * @throws \Exception
     */
    public function __construct(string $url,string $key,string $password)
    {
        $this->url=rtrim($url,'/');
        $this->key=$key;
        $this->password=$password;
    }

    /**
     * 生成获取当前位置坐标的url
     * @param string $callbackUrl 获取完成后，将数据重定向到此页面
     * @param array|null $params 其他参数，在callback_url中
     * @return string
     */
    public function generateLocationUrl(string $callbackUrl,array $params=null):string{
        return $this->generateUrl('GetLocation',[
            'callback_url'=>$callbackUrl,
        ],$params);
    }


    /**
     * 生成语音录制的url
     * @param string $callbackUrl 语音录制完成后，将数据重定向到此页面
     * @param bool $speex 是否生成speex格式的语音，否的话生成的是amr格式语音
     * @param array|null $params 其他参数，将会一起返回到callback_url中，使用$_GET['params']接收
     * @return string
     */
    public function generateRecordUrl(string $callbackUrl,bool $speex=false,array $params=null):string{
        return $this->generateUrl('Record',[
            'callback_url'=>$callbackUrl,
            'speex'=>$speex?1:0,
        ],$params);
    }

    /**
     * 生成下载语音的url或者语音播放的url
     * @param string $path 要下载的文件地址，如 gmc/20220720/164939/2_f3cae4f1873595ff997ece6ae91795d3.amr
     * @return string
     */
    public function generateRecordDownUrl(string $path):string{
        return $this->generateUrl('Scan',[
            'method'=>'down',
            'path'=>$path,
        ]);
    }



    /**
     * 调起二维码扫描结果
     * @param string $callbackUrl 获取扫描结果后，将数据重定向到此页面
     * @param array|null $params 其他参数，将会一起返回到callback_url中，使用$_GET['params']接收
     * @return string
     */
    public function generateScanUrl(string $callbackUrl,array $params=null):string{
        return $this->generateUrl('Scan',[
            'callback_url'=>$callbackUrl,
        ],$params);
    }


    /**
     * 获取微信用户openid
     * @param string $callbackUrl
     * @param array|null $params
     * @return string
     */
    public function generateOpenIdUrl(string $callbackUrl,array $params=null):string{
        return $this->generateUrl('GetOpenId',[
            'callback_url'=>$callbackUrl,
        ],$params);
    }



    public function generateUrl(string $type,array $other=[],array $params=null):string{
        $url=$this->url;//域名
        $key=$this->key;//名称
        $password=$this->password;//密码
        /***************************************************/

        $other['type']=$type;
        $other['nonce']=time();

        $chars = md5(uniqid(mt_rand(), true));
        $other['uuid']=substr ( $chars, 0, 8 ) . '-'
            . substr ( $chars, 8, 4 ) . '-'
            . substr ( $chars, 12, 4 ) . '-'
            . substr ( $chars, 16, 4 ) . '-'
            . substr ( $chars, 20, 12 );
        $params||$params=[];
        $params['__type']=$type;
        $params['__nonce']=$other['nonce'];

        // Must be exact 32 chars (256 bit)
        $password = substr(hash('sha256', $password, true), 0, 32);
        // IV must be exact 16 chars (128 bit)
        $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);

        $v=base64_encode(openssl_encrypt(serialize($other), 'AES-128-CBC', $password, OPENSSL_RAW_DATA, $iv));

        //缓存2小时
        \think\facade\Cache::tag('jcwx-sdk-generate-uuid')->set('jcwx-'.$other['uuid'],$params,60*60*2);
        return $url.'/index.php?k='.$key.'&v='.urlencode($v);
    }


    /**
     * 解析回调地址中的参数
     * @param bool $once 为了安全，一个请求只允许访问一次
     * @return array
     * @throws \Exception
     */
    public function getBackData(bool $once=true):array{
        $uuid=request()->get('uuid');
        if(!$uuid){
            throw new \Exception('缺少参数-00A');
        }
        $str=request()->get('res');
        if(!$str){
            throw new \Exception('缺少参数-00B');
        }

        $params= \think\facade\Cache::get('jcwx-'.$uuid);
        if(empty($params)){
            throw new \Exception('请求已过期或请求参数不合法-001');
        }


        $iv=substr(md5(chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0)),8,16);
        $ik=substr(md5(hash('sha256', $params['__type'].$params['__nonce'])),8,16);

        $json=openssl_decrypt($str, 'AES-128-CBC', $ik, OPENSSL_ZERO_PADDING ,$iv);
        $json||$json=openssl_decrypt(base64_decode($str)?:'', 'AES-128-CBC', $ik, OPENSSL_ZERO_PADDING ,$iv);
        $json||$json=openssl_decrypt(base64_decode($str)?:'', 'AES-128-CBC', $ik, OPENSSL_RAW_DATA ,$iv);
        $json||$json=openssl_decrypt(base64_decode($str)?:'', 'AES-128-CBC', substr(hash('sha256', $this->password, true), 0, 32), OPENSSL_RAW_DATA ,chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0));
        if(!$json){
            throw new \Exception('解析失败-00A');
        }

        //去除生成的特殊符号(16进制的符号)
        $json=trim($json);


        $str=strpos($json,'{');
        $end=strpos($json,'}');
        $str2=strpos($json,'[');
        $end2=strpos($json,']');
        if($str===0){
            $json=mb_substr($json,$str,$end+1);
        }else if($str!==false&&$str2!==false){
            if($str>$str2){
                $json=mb_substr($json,$str2,$end2+1);
            }else{
                $json=mb_substr($json,$str,$end+1);
            }
        }else if($str===false&&$str2!==false){
            $json=mb_substr($json,$str2,$end2+1);
        }

        if(!$json){
            throw new \Exception('解析失败-00A1');
        }

        $res=json_decode($json,true);
        if($res===null){
            throw new \Exception('解析失败-00B');
        }


        if($once){
            //为了安全只允许访问一次
            \think\facade\Cache::delete('jcwx-'.$uuid);
        }


        return [
            'res'=>$res,
            'params'=>$params,
        ];
    }


}