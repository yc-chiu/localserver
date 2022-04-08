function GetErrorMessage(nRc, language) {
  //alert("typeof(nRc)=="+ typeof(nRc) + " ,nRc=" + nRc);
   
  if(typeof(nRc)=="string"){ //from元件
    nRc = parseInt(nRc, 16);
    //alert(nRc);
  }else if (typeof(nRc)=="number"){ //from localServer
    ;
  }else{
    return "GetErrorMessage: typeof(nRc) is mismatched!";
  }
    
	var ErrMsg = "";
	var aryIdx = 0;
	if(language=="0"){
		aryIdx = 0;
	}else if(language=="1"){
		aryIdx = 1;
	}else if(language=="2"){
		aryIdx = 2;
	}
	
  
	if(typeof(aryErrorMessage[nRc])=="object"){
		ErrMsg = strErrorCode[aryIdx]+"0x"+parseInt(nRc, 10).toString(16)+strDescription[aryIdx]+aryErrorMessage[nRc][aryIdx];
	}else{ /* 發生未知的錯誤 */
		ErrMsg = strErrorCode[aryIdx]+"0x"+parseInt(nRc, 10).toString(16)+strDescription[aryIdx]+strUnknown[aryIdx];
	}
	return ErrMsg;
}

var strErrorCode = ['Error Code：','錯誤代碼：','错误代码：'];
var strDescription = [' Description：','說明：','说明：'];
var strUnknown = ['An unknown error occurred','發生未知的錯誤','发生未知的错误'];


var aryErrorMessage = [];
aryErrorMessage[0] = ['Success','成功','成功'];
//0x82開頭為自訂Token的錯誤代碼
aryErrorMessage[parseInt('82000001', 16)] = ['CRYPTO_PKCS7_TYPE_ERROR: Crypto TYPE error', 'CRYPTO_PKCS7_TYPE_ERROR: Crypto TYPE錯誤','CRYPTO_PKCS7_TYPE_ERROR: Crypto TYPE错误'];
aryErrorMessage[parseInt('82000002', 16)] = ['CRYPTO_PKCS7_GET_SIGNER: Crypto SIGNER error', 'CRYPTO_PKCS7_GET_SIGNER: Crypto SIGNER錯誤','CRYPTO_PKCS7_GET_SIGNER: Crypto SIGNER错误'];
aryErrorMessage[parseInt('82000003', 16)] = ['CRYPTO_PKCS7_SIGN_ERROR: Crypto SIGN error', 'CRYPTO_PKCS7_SIGN_ERROR: Crypto SIGN錯誤','CRYPTO_PKCS7_SIGN_ERROR: Crypto SIGN错误'];
aryErrorMessage[parseInt('82000004', 16)] = ['CRYPTO_PKCS7_VERIFY_FAIL: Crypto VERIFY error', 'CRYPTO_PKCS7_VERIFY_FAIL: Crypto VERIFY錯誤','CRYPTO_PKCS7_VERIFY_FAIL: Crypto VERIFY错误'];
aryErrorMessage[parseInt('82000005', 16)] = ['CRYPTO_PKCS7_ENCRYPT_ERROR: Crypto ENCRYPT error', 'CRYPTO_PKCS7_ENCRYPT_ERROR: Crypto ENCRYPT錯誤','CRYPTO_PKCS7_ENCRYPT_ERROR: Crypto ENCRYPT错误'];
aryErrorMessage[parseInt('82000006', 16)] = ['CRYPTO_PKCS7_DECRYPT_FAIL: Crypto DECRYPT error', 'CRYPTO_PKCS7_DECRYPT_FAIL: Crypto DECRYPT錯誤','CRYPTO_PKCS7_DECRYPT_FAIL: Crypto DECRYPT错误'];
aryErrorMessage[parseInt('82000007', 16)] = ['CRYPTO_PKCS7_FORMAT_CONVERT_ERROR: Crypto Format Convert error', 'CRYPTO_PKCS7_FORMAT_CONVERT_ERROR: Crypto Format Convert錯誤','CRYPTO_PKCS7_FORMAT_CONVERT_ERROR: Crypto Format Convert错误'];
aryErrorMessage[parseInt('82000011', 16)] = ['Time format conversion error', '時間格式轉換錯誤','时间格式转换错误'];
aryErrorMessage[parseInt('82000021', 16)] = ['Can not find Token-driven library', '找不到載具驅動函式庫','找不到载具驱动函式库'];
aryErrorMessage[parseInt('82000022', 16)] = ['An X509_REQ_sign error occurred during the production of the CSR','產生CSR過程中發生X509_REQ_sign錯誤','产生CSR过程中发生X509_REQ_sign错误'];
aryErrorMessage[parseInt('82000023', 16)] = ['Can not find key when the CSR content was checked', '檢驗CSR內容時發現找不到金鑰','检验CSR内容时发现找不到金钥'];
aryErrorMessage[parseInt('82000024', 16)] = ['X509_REQ_verify error occurred when the CSR content was checked', '檢驗CSR內容時發現X509_REQ_verify錯誤','检验CSR内容时发现X509_REQ_verify错误'];
aryErrorMessage[parseInt('82000025', 16)] = ['Certificate content read error (X509_NAME_print_ex error)', '憑證內容讀取錯誤(X509_NAME_print_ex錯誤)','凭证内容读取错误(X509_NAME_print_ex错误)'];
aryErrorMessage[parseInt('82000026', 16)] = ['Certificate parsing error (X509_NAME_get_index_by_NID error)', '憑證解析錯誤(X509_NAME_get_index_by_NID錯誤)','凭证解析错误(X509_NAME_get_index_by_NID错误)'];
aryErrorMessage[parseInt('82000031', 16)] = ['Can not find any object in Token', '載具內找不到任何object','载具内找不到任何object'];
aryErrorMessage[parseInt('82000033', 16)] = ['Can not find the specific certificate in Token(by Modulus)', '載具內找不到特定的憑證(by Modulus)','载具内找不到特定的凭证(by Modulus)'];
aryErrorMessage[parseInt('82000034', 16)] = ['DigestInfo is too large', 'DigestInfo資料過大','DigestInfo资料过大'];
aryErrorMessage[parseInt('82000035', 16)] = ['RawSign Sign error', 'RawSign簽章錯誤','RawSign签章错误'];
//0x81開頭為元件所定義的錯誤代碼
aryErrorMessage[parseInt('81000001', 16)] = ['User cancel the operation', '使用者取消操作','使用者取消操作'];
aryErrorMessage[parseInt('81000002', 16)] = ['Please enter PIN', '未輸入載具密碼','未输入载具密码'];
aryErrorMessage[parseInt('81000003', 16)] = ['Please enter Graphic verification code', '未輸入圖形辨識碼','未输入图形辨识码'];
aryErrorMessage[parseInt('81000004', 16)] = ['Graphic verification code validation failed', '圖形辨識碼輸入錯誤','图形辨识码输入错误'];
aryErrorMessage[parseInt('81000005', 16)] = ['Dynamic keyboard number validation failed', '動態鍵盤確定鍵輸入錯誤','动态键盘确定键输入错误'];
aryErrorMessage[parseInt('81000006', 16)] = ['Make sure the new password and confirm password are the same', '輸入新密碼與再次輸入新密碼不相符','输入新密码与再次输入新密码不相符'];
aryErrorMessage[parseInt('81000007', 16)] = ['Timeout, Exceeds the waiting time to Remove Token and Re-plugin', '未在指定時間內執行插拔載具動作','未在指定时间内执行插拔载具动作'];
aryErrorMessage[parseInt('81000008', 16)] = ['Non trusted domain', '非合法網域使用','非合法网域使用'];
aryErrorMessage[parseInt('81000009', 16)] = ['Can not find Token-driven library', '找不到載具驅動函式庫','找不到载具驱动函式库'];
aryErrorMessage[parseInt('8100000A', 16)] = ['Can not find Token', '找不到載具','找不到载具'];
aryErrorMessage[parseInt('8100000B', 16)] = ['The certificate does not exist or the user does not select', '憑證不存在或使用者未點選','凭证不存在或使用者未点选'];
aryErrorMessage[parseInt('8100000C', 16)] = ['There are no keys in Token', '載具中不存在任何金鑰','载具中不存在任何金钥'];
aryErrorMessage[parseInt('8100000D', 16)] = ['Certificate content error ', '憑證有錯誤','凭证有错误'];
aryErrorMessage[parseInt('8100000E', 16)] = ['Can not find the corresponding key associated with the certificate ', '找不到和憑證相對應的金鑰','找不到和凭证相对应的金钥'];
aryErrorMessage[parseInt('8100000F', 16)] = ['Can not find any object(key/certificate) in Token', '載具中找不到Object(金鑰和憑證)','载具中找不到对象（金钥和凭证）'];
aryErrorMessage[parseInt('81000010', 16)] = ['Signature output data error (length = 0)', '簽章輸出資料錯誤(長度=0)','签章输出资料错误（长度= 0）'];
aryErrorMessage[parseInt('81000011', 16)] = ['Refused to write duplicate certificate', '拒絕重複寫入憑證','拒绝重复写入凭证'];
aryErrorMessage[parseInt('81000012', 16)] = ['Token Open session failed', '載具Session開啟失敗','载具Session开启失败'];
aryErrorMessage[parseInt('81000013', 16)] = ['Read Token information failed', '讀取載具資訊失敗','读取载具资讯失败'];
aryErrorMessage[parseInt('81000014', 16)] = ['Token AES encryption failed', '載具AES加密失敗','载具AES加密失败'];
aryErrorMessage[parseInt('81000015', 16)] = ['Invalid input parameter', '輸入參數無效','输入参数无效'];
aryErrorMessage[parseInt('81000016', 16)] = ['OTP mismatch', 'OTP不符合','OTP不符合'];
aryErrorMessage[parseInt('81000017', 16)] = ['RSA encryption failed', 'RSA加密失敗','RSA加密失败'];
aryErrorMessage[parseInt('81000018', 16)] = ['RSA decryption failed', 'RSA解密失敗','RSA解密失败'];
aryErrorMessage[parseInt('81000019', 16)] = ['AES encryption failed', 'AES加密失敗','AES加密失败'];
aryErrorMessage[parseInt('8100001A', 16)] = ['AES decryption failed', 'AES解密失敗','AES解密失败'];
aryErrorMessage[parseInt('8100001B', 16)] = ['Token Serial Nummber mismatched between detction and parameter parsing', '需求參數比對時，與偵測到的載具序號不符合','需求参数比对时，与侦测到的载具序号不符合'];
aryErrorMessage[parseInt('8100001C', 16)] = ['Can not find importKey', '找不到importKey','找不到importKey'];
aryErrorMessage[parseInt('8100001D', 16)] = ['OTP does not exist', '元件OTP不存在','元件OTP不存在'];
aryErrorMessage[parseInt('8100001E', 16)] = ['Token Serial Nummber mismatched between OTP generation and parameter parsing', '需求參數比對時，與元件產生OTP時偵測到的載具序號不符合','需求参数比对时，与元件产生OTP时侦测到的载具序号不符合'];
aryErrorMessage[parseInt('8100001F', 16)] = ['Memory allocation failed', '配置記憶體錯誤','配置记忆体错误'];
aryErrorMessage[parseInt('81000020', 16)] = ['RawSign Sign error', 'RawSign簽章錯誤','RawSign签章错误'];
aryErrorMessage[parseInt('81000021', 16)] = ['RawSign Verify error', 'RawSign簽章驗證錯誤','RawSign签章验证错误'];
aryErrorMessage[parseInt('81000022', 16)] = ['PKCS7 envelope encrypted data error', 'P7數位信封加密錯誤','数位信封加密错误'];
aryErrorMessage[parseInt('81000023', 16)] = ['PKCS7 envelope decrypted data  error', 'P7數位信封解密錯誤','数位信封解密错误'];
aryErrorMessage[parseInt('81000024', 16)] = ['DigestInfo is too large', 'DigestInfo資料過大','DigestInfo资料过大'];
aryErrorMessage[parseInt('81000025', 16)] = ['PKCS1 Sign error', 'PKCS1簽章錯誤','PKCS1签章错误'];
aryErrorMessage[parseInt('81000026', 16)] = ['PKCS1 Verify error', 'PKCS1簽章驗證錯誤','PKCS1签章验证错误'];
aryErrorMessage[parseInt('81000027', 16)] = ['There are multiple certificates. Please set the certificate filter to specify one certificate.', '存在多張憑證，請設定憑證列舉條件以指定一張憑證。','存在多张凭证，请设定凭证列举条件以指定一张凭证'];
aryErrorMessage[parseInt('81000100', 16)] = ['Can not find Token-driven library when initialize/Unblock Token', '初始化或鎖卡解碼時，找不到載具驅動函式庫','初始化或锁卡解码时，找不到载具驱动函式库'];
aryErrorMessage[parseInt('81000101', 16)] = ['Create Secret Key failed when initialize Token', '初始化時，載具建立Secret Key錯誤','初始化时，载具建立Secret Key错误'];
aryErrorMessage[parseInt('81000102', 16)] = ['Login type failed when initialize/Unblock Token', '初始化或鎖卡解碼時，登入使用者類別錯誤','初始化或锁卡解码时，登入使用者类别错误'];
aryErrorMessage[parseInt('81000103', 16)] = ['Can not find Token when initialize/Unblock Token', '初始化或鎖卡解碼時，找不到載具','初始化或锁卡解码时，找不到载具'];
aryErrorMessage[parseInt('81000104', 16)] = ['This feature is not supported for the specified Token type when initialize/Unblock Token', '初始化或鎖卡解碼時，指定的載具類別不支援此功能','初始化或锁卡解码时，指定的载具类别不支援此功能'];

aryErrorMessage[parseInt('81000105', 16)] = ['Decode BASE64 error when initialize/Unblock Token', '初始化或鎖卡解碼時，Decode BASSE64 錯誤','初始化或锁卡解码时，Decode BASSE64 错误'];
aryErrorMessage[parseInt('81000106', 16)] = ['The format of parameter soPIN is wrong when initialize/Unblock Token', '初始化或鎖卡解碼時，參數soPIN格式錯誤','初始化或锁卡解码时，参数soPIN格式错误'];
aryErrorMessage[parseInt('81000107', 16)] = ['The date of parameter soPIN is wrong when initialize/Unblock Token', '初始化或鎖卡解碼時，參數soPIN的日期錯誤','初始化或锁卡解码时，参数soPIN的日期错误'];
aryErrorMessage[parseInt('81000108', 16)] = ['soPIN decryption failed when initialize/Unblock Token', '初始化或鎖卡解碼時，soPIN解密失敗','初始化或锁卡解码时，soPIN解密失败'];
aryErrorMessage[parseInt('81000109', 16)] = ['The parameter tokenObjectValue is empty when initialize/Unblock Token', '初始化或鎖卡解碼時，參數tokenObjectValue未指定','初始化或锁卡解码时，参数tokenObjectValue未指定'];
aryErrorMessage[parseInt('8100010A', 16)] = ['The parameter userPIN is empty when initialize/Unblock Token', '初始化或鎖卡解碼時，參數userPIN未指定','初始化或锁卡解码时，参数userPIN未指定'];

aryErrorMessage[parseInt('81000200', 16)] = ['Get local system time failed', '元件取得local系統時間失敗','元件取得local系统时间失败'];
aryErrorMessage[parseInt('81000201', 16)] = ['Initial connection request has expired', '初始連線需求已過期限','初始连线需求已过期限'];
aryErrorMessage[parseInt('81000202', 16)] = ['Signature verification failed when initial connection', '初始連線時元件驗簽章失敗','初始连线时元件验签章失败'];
aryErrorMessage[parseInt('81000203', 16)] = ['JSON parsing failed', 'JSON解析失敗','JSON解析失败'];
aryErrorMessage[parseInt('81000204', 16)] = ['JSON parsing failed(function name error)', 'JSON解析主要函式名稱失敗','JSON解析主要函式名称失败'];
aryErrorMessage[parseInt('81000205', 16)] = ['JSON parsing failed(parameter error)', 'JSON解析參數失敗','JSON解析参数失败'];
aryErrorMessage[parseInt('81000206', 16)] = ['Multi-level JSON parsing failed', '多階JSON解析失敗','多阶JSON解析失败'];
aryErrorMessage[parseInt('81000207', 16)] = ['Multi-level JSON parsing failed(function name error)', '多階JSON解析主要函式名稱失敗','多阶JSON解析主要函式名称失败'];
aryErrorMessage[parseInt('81000208', 16)] = ['Can not get UTC when initial connection', '初始連線時無法取得UTC','初始连线时无法取得UTC'];
aryErrorMessage[parseInt('81000209', 16)] = ['AES key does not exist', 'AES金鑰不存在','AES金钥不存在'];
//0x80開頭為載具Vendor自訂
//GoTrust載具回覆PIN錯誤，非000000A0，而是0x800{e-1}00a0，ex:0x800e00a0、0x800d00a0、0x800100a0…
aryErrorMessage[parseInt('0x800e00a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800d00a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800c00a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800b00a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800a00a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800900a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800800a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800700a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800600a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800500a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800400a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800300a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800200a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('0x800100a0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
//0x83開頭為自訂LocalServer的錯誤代碼
aryErrorMessage[parseInt('83000001', 16)] = ['Non trusted domain', '未授權的網站','未授权的网站'];
aryErrorMessage[parseInt('83000002', 16)] = ['Connection URL Path error', '錯誤的連線路徑','错误的连线路径'];
aryErrorMessage[parseInt('83000003', 16)] = ['String conversion failed for requested command', '需求指令字串轉換處理有誤','需求指令字串转换处理有误'];
//若非0x80、0x81、0x82、0x83開頭，則為PKCS11函式庫定義的錯誤代碼(由PKCS #11 模組回覆)
aryErrorMessage[parseInt('00000001', 16)] = ['CKR_CANCEL: Function terminates abnormally', 'CKR_CANCEL: 函式異常終止','CKR_CANCEL: 函式异常终止'];
aryErrorMessage[parseInt('00000002', 16)] = ['CKR_HOST_MEMORY: Memory allocation failed', 'CKR_HOST_MEMORY: 記憶體配置失敗','CKR_HOST_MEMORY：记忆体配置失败'];
aryErrorMessage[parseInt('00000003', 16)] = ['CKR_SLOT_ID_INVALID: The specified slot ID is invalid', 'CKR_SLOT_ID_INVALID: 指定的slot ID無效','CKR_SLOT_ID_INVALID：指定的slot ID无效'];
aryErrorMessage[parseInt('00000005', 16)] = ['CKR_GENERAL_ERROR: Unrecoverable error', 'CKR_GENERAL_ERROR: 遇到了一個無法恢復的錯誤','CKR_GENERAL_ERROR：遇到了一个无法恢复的错误'];
aryErrorMessage[parseInt('00000006', 16)] = ['CKR_FUNCTION_FAILED: The requested function could not be executed', 'CKR_FUNCTION_FAILED: 請求的函式無法被執行','CKR_FUNCTION_FAILED：请求的函数无法被执行'];
aryErrorMessage[parseInt('00000007', 16)] = ['CKR_ARGUMENTS_BAD: Incorrect input parameter', 'CKR_ARGUMENTS_BAD: 輸入參數錯誤','CKR_ARGUMENTS_BAD：输入参数错误'];
aryErrorMessage[parseInt('00000020', 16)] = ['CKR_DATA_INVALID: The plaintext input data for the encryption operation is invalid', 'CKR_DATA_INVALID: 加密操作的明文輸入數據是無效的','CKR_DATA_INVALID：加密操作的明文输入数据是无效的'];
aryErrorMessage[parseInt('00000021', 16)] = ['CKR_DATA_LEN_RANGE: The plaintext input length of the encryption operation is incorrect', 'CKR_DATA_LEN_RANGE: 加密操作的明文輸入數據長度有誤','CKR_DATA_LEN_RANGE：加密操作的明文输入数据长度有误'];
aryErrorMessage[parseInt('00000030', 16)] = ['CKR_DEVICE_ERROR: Token abnormal', 'CKR_DEVICE_ERROR: 載具異常','CKR_DEVICE_ERROR：载具异常'];
aryErrorMessage[parseInt('00000031', 16)] = ['CKR_DEVICE_MEMORY: Token is out of memory', 'CKR_DEVICE_MEMORY: 載具沒有足夠的記憶體空間','CKR_DEVICE_MEMORY：载具没有足够的记忆体空间'];
aryErrorMessage[parseInt('00000032', 16)] = ['CKR_DEVICE_REMOVED: Token was removed during the execution of the function', 'CKR_DEVICE_REMOVED: 函式執行過程中載具被移除','CKR_DEVICE_REMOVED：函式执行过程中载具被移除'];
aryErrorMessage[parseInt('00000040', 16)] = ['CKR_ENCRYPTED_DATA_INVALID: The encryption input for the decryption operation is an invalid ciphertext', 'CKR_ENCRYPTED_DATA_INVALID: 解密操作的加密輸入為無效密文','CKR_ENCRYPTED_DATA_INVALID: 解密操作的加密输入为无效密文'];
aryErrorMessage[parseInt('00000041', 16)] = ['CKR_ENCRYPTED_DATA_LEN_RANGE: The encrypted input length of the decryption operation is incorrect and becomes invalid.', 'CKR_ENCRYPTED_DATA_LEN_RANGE: 解密操作的加密輸入長度有誤而成為無效密文','CKR_ENCRYPTED_DATA_LEN_RANGE: 解密操作的加密输入长度有误而成为无效密文'];
aryErrorMessage[parseInt('00000050', 16)] = ['CKR_FUNCTION_CANCELED: The function was canceled in execution', 'CKR_FUNCTION_CANCELED: 函式在執行中被取消','CKR_FUNCTION_CANCELED: 函式在执行中被取消'];
aryErrorMessage[parseInt('00000051', 16)] = ['CKR_FUNCTION_NOT_PARALLEL: No function is executed in parallel in the specified session', 'CKR_FUNCTION_NOT_PARALLEL: 在指定的session中沒有函式併行執行','CKR_FUNCTION_NOT_PARALLEL: 在指定的session中没有函式并行执行'];
aryErrorMessage[parseInt('00000054', 16)] = ['CKR_FUNCTION_NOT_SUPPORTED: The request function is not supported by the Cryptoki library', 'CKR_FUNCTION_NOT_SUPPORTED: Cryptoki函式庫不支援該請求函式','CKR_FUNCTION_NOT_SUPPORTED: Cryptoki函式库不支援该请求函式'];
aryErrorMessage[parseInt('00000060', 16)] = ['CKR_KEY_HANDLE_INVALID: The specified key handle is invalid', 'CKR_KEY_HANDLE_INVALID: 指定的密鑰handle無效','CKR_KEY_HANDLE_INVALID: 指定的密钥handle无效'];
aryErrorMessage[parseInt('00000062', 16)] = ['CKR_KEY_SIZE_RANGE: Although the request key encryption operation can be performed in principle, the Cryptoki library can not actually be completed because the size of the key provided exceeds the range of the key size it can manage', 'CKR_KEY_SIZE_RANGE: 儘管請求密鑰加密操作原則上可以執行，但該Cryptoki函式庫實際上並不能完成，這是因為提供的密鑰的尺寸超出了它能管理的密鑰尺寸的範圍','CKR_KEY_SIZE_RANGE: 尽管请求密钥加密操作原则上可以执行，但该Cryptoki函式库实际上并不能完成，这是因为提供的密钥的尺寸超出了它能管理的密钥尺寸的范围'];
aryErrorMessage[parseInt('00000063', 16)] = ['CKR_KEY_TYPE_INCONSISTENT: The specified key is not the correct type of key used by the specified mechanism', 'CKR_KEY_TYPE_INCONSISTENT: 指定的密鑰不是配合指定的機制使用的正確類型的密鑰','CKR_KEY_TYPE_INCONSISTENT: 指定的密钥不是配合指定的机制使用的正确类型的密钥'];
aryErrorMessage[parseInt('00000082', 16)] = ['CKR_OBJECT_HANDLE_INVALID: Object handle is invalid', 'CKR_OBJECT_HANDLE_INVALID: Object handle無效','CKR_OBJECT_HANDLE_INVALID: Object handle无效'];
aryErrorMessage[parseInt('00000090', 16)] = ['CKR_OPERATION_ACTIVE: Another operation is already active. For example, Token PIN expires', 'CKR_OPERATION_ACTIVE: 另一個操作已經觸發. 如:載具PIN碼到期','CKR_OPERATION_ACTIVE: 另一个操作已经触发. 如:载具PIN码到期'];
aryErrorMessage[parseInt('000000A0', 16)] = ['CKR_PIN_INCORRECT: The PIN entered and the PIN in the Token are not match ', 'CKR_PIN_INCORRECT: 輸入的PIN碼與載具內的PIN碼不符合','CKR_PIN_INCORRECT: 输入的PIN码与载具内的PIN码不符合'];
aryErrorMessage[parseInt('000000A1', 16)] = ['CKR_PIN_INVALID: The entered PIN is invalid. For example, the new PIN has to meet the strength setting, or can not be the same as the most recently used PIN', 'CKR_PIN_INVALID: 輸入的PIN碼無效. 如:新密碼必符合強度設定，或不可與最近使用的密碼相同','CKR_PIN_INVALID: 输入的PIN码无效. 如:新密码必符合强度设定，或不可与最近使用的密码相同'];
aryErrorMessage[parseInt('000000A2', 16)] = ['CKR_PIN_LEN_RANGE: The PIN entered is too long or too short', 'CKR_PIN_LEN_RANGE: 輸入的PIN碼長度太長或太短','CKR_PIN_LEN_RANGE：输入的PIN码长度太长或太短'];
aryErrorMessage[parseInt('000000A3', 16)] = ['CKR_PIN_EXPIRED: Token PIN expires', 'CKR_PIN_EXPIRED: 載具PIN碼到期','CKR_PIN_EXPIRED：载具PIN码到期'];
aryErrorMessage[parseInt('000000A4', 16)] = ['CKR_PIN_LOCKED: Token PIN lock', 'CKR_PIN_LOCKED: 載具PIN碼鎖定','CKR_PIN_LOCKED：载具PIN码锁定'];
aryErrorMessage[parseInt('000000B0', 16)] = ['CKR_SESSION_CLOSED: Session is closed during function execution', 'CKR_SESSION_CLOSED: 函式執行過程中Session被關閉','CKR_SESSION_CLOSED：函式执行过程中Session被关闭'];
aryErrorMessage[parseInt('000000B1', 16)] = ['CKR_SESSION_COUNT: Session Open failed because the Token has opened too many sessions', 'CKR_SESSION_COUNT: Session開啟失敗，因為載具已開啟太多Sessions','CKR_SESSION_COUNT：Session开启失败，因为载具已开启太多Sessions'];
aryErrorMessage[parseInt('000000B3', 16)] = ['CKR_SESSION_HANDLE_INVALID: Session handle is invalid', 'CKR_SESSION_HANDLE_INVALID: Session handle無效','CKR_SESSION_HANDLE_INVALID：Session handle无效'];
aryErrorMessage[parseInt('000000B4', 16)] = ['CKR_SESSION_PARALLEL_NOT_SUPPORTED: The Token does not support parallel sessions', 'CKR_SESSION_PARALLEL_NOT_SUPPORTED: 載具不支援併行Sessions','CKR_SESSION_PARALLEL_NOT_SUPPORTED：载具不支援并行Sessions'];
aryErrorMessage[parseInt('000000B5', 16)] = ['CKR_SESSION_READ_ONLY: Session is read-only, so it can not complete the desired action', 'CKR_SESSION_READ_ONLY: Session為唯讀因此無法完成想要的執行動作','CKR_SESSION_READ_ONLY：Session为唯读因此无法完成想要的执行动作'];
aryErrorMessage[parseInt('000000B6', 16)] = ['CKR_SESSION_EXISTS: Session is already open, so the Token can not be initialized', 'CKR_SESSION_EXISTS: Session已經開啟因此載具無法被初始化','CKR_SESSION_EXISTS：Session已经开启因此载具无法被初始化'];
aryErrorMessage[parseInt('000000B7', 16)] = ['CKR_SESSION_READ_ONLY_EXISTS: Read-only session already exists, so SO can not login', 'CKR_SESSION_READ_ONLY_EXISTS: 唯讀Session已經存在因此SO無法登入','CKR_SESSION_READ_ONLY_EXISTS：唯读Session已经存在因此SO无法登入'];
aryErrorMessage[parseInt('000000B8', 16)] = ['CKR_SESSION_READ_WRITE_SO_EXISTS: Read-Write SO Session already exists, so it can not open read-only Session', 'CKR_SESSION_READ_WRITE_SO_EXISTS: 讀寫SO Session已經存在，因此無法開啟唯讀Session','CKR_SESSION_READ_WRITE_SO_EXISTS: 读写SO Session已经存在，因此无法开启唯读Session'];
aryErrorMessage[parseInt('000000C0', 16)] = ['CKR_SIGNATURE_INVALID: Invalid signature', 'CKR_SIGNATURE_INVALID: 簽章無效','CKR_SIGNATURE_INVALID：签章无效'];
aryErrorMessage[parseInt('000000C1', 16)] = ['CKR_SIGNATURE_LEN_RANGE: The length of the signature is incorrect and becomes an invalid ', 'CKR_SIGNATURE_LEN_RANGE: 簽章長度有誤而成為無效簽章','CKR_SIGNATURE_LEN_RANGE：签章长度有误而成为无效签章'];
aryErrorMessage[parseInt('000000E0', 16)] = ['CKR_TOKEN_NOT_PRESENT: The Token does not exist', 'CKR_TOKEN_NOT_PRESENT: 載具不存在','CKR_TOKEN_NOT_PRESENT：载具不存在'];
aryErrorMessage[parseInt('000000E1', 16)] = ['CKR_TOKEN_NOT_RECOGNIZED: Cryptoki library or slot does not recognize the Token', 'CKR_TOKEN_NOT_RECOGNIZED: Cryptoki函式庫或slot無法識別該載具','CKR_TOKEN_NOT_RECOGNIZED：Cryptoki函数库或slot无法识别该载具'];
aryErrorMessage[parseInt('000000E2', 16)] = ['CKR_TOKEN_WRITE_PROTECTED: Token has write protection, so it can not perform the request', 'CKR_TOKEN_WRITE_PROTECTED: 載具有防止寫入保護，因此無法執行請求的動作','CKR_TOKEN_WRITE_PROTECTED: 载具有防止写入保护，因此无法执行请求的动作'];
aryErrorMessage[parseInt('00000100', 16)] = ['CKR_USER_ALREADY_LOGGED_IN: The user is already logged in and can not allow duplicate login', 'CKR_USER_ALREADY_LOGGED_IN: 該使用者已經登入，無法允許重複登入','CKR_USER_ALREADY_LOGGED_IN: 该使用者已经登入，无法允许重复登入'];
aryErrorMessage[parseInt('00000101', 16)] = ['CKR_USER_NOT_LOGGED_IN: The user is not logged in', 'CKR_USER_NOT_LOGGED_IN: 使用者未登入','CKR_USER_NOT_LOGGED_IN: 使用者未登入'];
aryErrorMessage[parseInt('00000102', 16)] = ['CKR_USER_PIN_NOT_INITIALIZED: PIN has not been initialized', 'CKR_USER_PIN_NOT_INITIALIZED: PIN碼尚未被初始化','CKR_USER_PIN_NOT_INITIALIZED: PIN码尚未被初始化'];
aryErrorMessage[parseInt('00000103', 16)] = ['CKR_USER_TYPE_INVALID: Invalid user type (valid type is CKU_SO / CKU_USER)', 'CKR_USER_TYPE_INVALID: 使用者類型無效(有效類型為CKU_SO/CKU_USER)','CKR_USER_TYPE_INVALID: 使用者类型无效(有效类型为CKU_SO/CKU_USER)'];
aryErrorMessage[parseInt('00000104', 16)] = ['CKR_USER_ANOTHER_ALREADY_LOGGED_IN: Other users have logged in with the same app, so they can no longer login', 'CKR_USER_ANOTHER_ALREADY_LOGGED_IN:已經有其他使用者透過同一個應用程式登入，因此無法再允許登入','CKR_USER_ANOTHER_ALREADY_LOGGED_IN:已经有其他使用者透过同一个应用程式登入，因此无法再允许登入'];
aryErrorMessage[parseInt('00000105', 16)] = ['CKR_USER_TOO_MANY_TYPES: Other users have already logged in with another app, so they can no longer login', 'CKR_USER_TOO_MANY_TYPES: 已經有其他使用者透過另一個應用程式登入，因此無法再允許登入','CKR_USER_TOO_MANY_TYPES: 已经有其他使用者透过另一个应用程式登入，因此无法再允许登入'];
aryErrorMessage[parseInt('00000150', 16)] = ['CKR_BUFFER_TOO_SMALL: Out of buffer', 'CKR_BUFFER_TOO_SMALL: 緩衝區不足','CKR_BUFFER_TOO_SMALL: 缓冲区不足'];
aryErrorMessage[parseInt('00000190', 16)] = ['CKR_CRYPTOKI_NOT_INITIALIZED: Cryptoki library is not initialized, so function can not be executed', 'CKR_CRYPTOKI_NOT_INITIALIZED: Cryptoki函式庫未初始化因而函數不能執行','CKR_CRYPTOKI_NOT_INITIALIZED：Cryptoki的函式库未初始化因而函数不能执行'];



