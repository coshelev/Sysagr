Процедура АвторизацияБезПользователяИЗагрузка() Экспорт	
	//Источник: https://developers.google.com/identity/protocols/OAuth2ServiceAccount
	//--------------------------------------------------------------------------------
		
	//Заголовок JWT 
	JWTheader 	= "{""alg"":""RS256"",""typ"":""JWT""}";

	//Заголовок JWT, закодированный в Base64 (в примере закодирован через беспратный онлайн-кодировщик: Base64URL_encoded_JWT_header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
	Base64URL_encoded_JWT_header = Binary2Base64UrlStr(Str2Binary(JWTheader));
	
	//exp The expiration time of the assertion, specified as seconds since 00:00:00 UTC, January 1, 1970. This value has a maximum of 1 hour after the issued time.
	ВремяИстеченияUTC 	= УниверсальноеВремя(ТекущаяДата())+60*60;
	СекундДо 			= ВремяИстеченияUTC - Дата(1970,1,1);
	exp 				= Строка(СекундДо);  
	exp 				= СтрЗаменить(exp, Символ(160), "");
	
	//iat 	The time the assertion was issued, specified as seconds since 00:00:00 UTC, January 1, 1970.
	iat = Строка(СекундДо-60*60);			
	iat = СтрЗаменить(iat, Символ(160), "");
	
	//JWT набор иструкций. Переносы строк и лишние пробелы не допускаются, т.к. лишние символы повлияют на кодировку в Base64
	//iss   - The email address of the service account, у нас notifyme348-419@sysagr1-196811.iam.gserviceaccount.com
	//scope - A space-delimited list of the permissions that the application requests.    
	//В следующей строке значение 1328554385 оставлено для примера, далее заменяется на нужные exp и iat    
	
	//JWTClaimSet = "{""iss"":""notifyme348-419@sysagr1-196811.iam.gserviceaccount.com"",""scope"":""https://www.googleapis.com/auth/contacts"",""aud"":""https://www.googleapis.com/oauth2/v4/token"",""exp"":1328554385,""iat"":1328550785} ";
	JWTClaimSet = "{""iss"":""notifyme348-419@sysagr1-196811.iam.gserviceaccount.com"", ""scope"":""https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/contacts.readonly https://www.googleapis.com/auth/contacts.other.readonly"",""aud"":""https://www.googleapis.com/oauth2/v4/token"",""exp"":1328554385,""iat"":1328550785} ";
	JWTClaimSet = СтрЗаменить(JWTClaimSet, "1328554385", exp); 
	JWTClaimSet = СтрЗаменить(JWTClaimSet, "1328550785", iat);
	
	//JWT набор иструкций, закодированный в Base64. Пример: Base64URL_encoded_JWTClaimSet = "eyJhdWQiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvdG9rZW4iLCJleHAiOjE1MjI5MjQ2NzYsImlhdCI6MTUyMjkyMTA3NiwiaXNzIjoibm90aWZ5bWUzNDgtNDE5QHN5c2FncjEtMTk2ODExLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwic2NvcGUiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL3NwcmVhZHNoZWV0cyJ9";
	Base64URL_encoded_JWTClaimSet 	=	Binary2Base64UrlStr(Str2Binary(JWTClaimSet));
	
	//Входящие данные для получения JWS
	inputForJWS = Base64URL_encoded_JWT_header+"."+Base64URL_encoded_JWTClaimSet;
	
	Хеширование = Новый ХешированиеДанных(ХешФункция.SHA256);
	Хеширование.Добавить(inputForJWS);
	ХешДвоичный = Хеширование.ХешСумма;
	
	//Чтение закрытого ключа
	СтруктураСертификата = ПолучитьСтруктуруСертификата();
	Если СтруктураСертификата = Неопределено Тогда
		ЗаписьЖурналаРегистрации("ПолучитьСтруктуруСертификата", УровеньЖурналаРегистрации.Ошибка,,, "Не получен закрытый ключ");
		Возврат                                                                                                               
	КонецЕсли;

	ПодписьДвоичная = ПолучиьПодписьSHA256RSA(ХешДвоичный, СтруктураСертификата);
	Подпись64 		= Binary2Base64UrlStr(ПодписьДвоичная);
	
	//Вычислить  JSON Web Signature (в примере JWT   = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjQvdG9rZW4iLCJleHAiOjE1MjI5MzI0MzAsImlhdCI6MTUyMjkyODgzMCwiaXNzIjoibm90aWZ5bWUzNDgtNDE5QHN5c2FncjEtMTk2ODExLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwic2NvcGUiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL3NwcmVhZHNoZWV0cyJ9.FyXnKxnJSfMwdVLRnPKPyaP4nefX12-CUYQ9AFbd5QdrVmq8OdH-pd-_lC8f_pJ8FMoSmjzV3AZm1A64kPrPfTaQM3JcaBrJGcGOxn1O8cSY5lDNpbxzmW4cIpAP9QsnNRWD9ysytLxykd2euH3gyyH7U2prBk83QZoLSTnBnh0y86H8_huA1ovuo7LlbgfYn1UF0gwYWEtU3hwjBsSZ1Ub33nKSd0SI1GAOTdXGkJIZkA1akW41IS4kP4L9tpP0yOIXnL0VSANI5g53gJGBj5nlbhNX_AATb1C97eDiF1zT8hd6FbEEVve2MpFSds3szXvN5FwGlc5o7Me40vRA2g";)
	JWT = inputForJWS+"."+Подпись64;
	
	//Запрос на получение Access token
	кмд   = "curl -X POST 'https://www.googleapis.com/oauth2/v4/token' -H 'Content-Type:application/x-www-form-urlencoded' -d 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="+JWT+"'";
	Ответ = Авито.CURL_HttpResponse(кмд);                                                                                              

	Если Ответ.КодСостояния <> 200 Тогда
		Сообщить(СтрШаблон("Ошибка: Ответ.КодСостояния = %1", Ответ.КодСостояния));
		ЗаписьЖурналаРегистрации("АвторизацияБезПользователяИЗагрузка()", УровеньЖурналаРегистрации.Ошибка,, кмд, "HTTP response code <> 200" );
		Возврат; 
	КонецЕсли;	
	
	Стр = Ответ.ПолучитьТелоКакСтроку();
	
	Об = Авито.ПрочитатьЗначениеJSON(Стр);
	
	AccessToken = Об.access_token;  	// живет 1 час, нужно получать новый с помощью refresh_token

	ПолучиДанные(AccessToken);

КонецПроцедуры

Процедура ПолучиДанные(AccessToken)
	//Собственно получение данных
	//-----------------------------
		
	//Spreadsheet ID (см. https://developers.google.com/sheets/api/guides/concepts#spreadsheet_id)
	//Every API method requires a spreadsheetId parameter which is used to identify which spreadsheet is to be accessed or altered. 
	//--------------------------------------------------------------------------------------------------------------------------------	
	spreadsheetId="1rMYnx6YTp6qnssSOg-rU64UczMZ3cFdxWVsMNf-uAtw"; 		//книга notifyme348@gmail.com_SysAgr_for_Adwords из аккаунта notifyme348@gmail.com 				- работает
	
	//Прочитай диапазон из spreasheet.Чтение Sheet2 - количества заполненных строк на листе Sheet1. Using the HTTP Authorization header like this: Authorization: Bearer oauth2-token
	//----------------------------------------------------------------------------------------------------------------------
	//кмд = СтрШаблон("curl -X GET 'https://people.googleapis.com/v1/people/me/connections?personFields=names,emailAddresses' -H 'Authorization:Bearer %1,' -H 'Content-Type:application/x-www-form-urlencoded'", AccessToken);	 //не работает
	//кмд = СтрШаблон("curl -X GET 'https://people.googleapis.com/v1/people/me' -H 'Authorization:Bearer %1,' -H 'Content-Type:application/x-www-form-urlencoded'", AccessToken); // не работает
	
	//кмд = СтрШаблон("curl -X GET 'https://people.googleapis.com/v1/contactGroups' -H 'Authorization:Bearer %1,' -H 'Content-Type:application/x-www-form-urlencoded'", AccessToken);	// это работает, возвращает список групп
	//кмд = СтрШаблон("curl -X GET 'https://people.googleapis.com/v1/otherContacts?readMask=names,emailAddresses' -H 'Authorization:Bearer %1,' -H 'Content-Type:application/x-www-form-urlencoded'", AccessToken);	// возвращает пустой json
	
	//Кэширующий запрос
	ТекДата = ТекущаяДата();
	кмд = СтрШаблон("curl -X GET 'https://people.googleapis.com/v1/people:searchContacts?query=&readMask=names,emailAddresses' -H 'Authorization:Bearer %1,' -H 'Content-Type:application/x-www-form-urlencoded'", AccessToken);	// возвращает пустой json
	Ответ = Авито.CURL_HttpResponse(кмд);	
	Если Ответ.КодСостояния <> 200 Тогда
		Возврат;
	КонецЕсли;  
	//Пауза
	Пока Истина Цикл
		Если ТекущаяДата()> ТекДата Тогда
			Прервать;
		КонецЕсли;
	КонецЦикла;
	кмд = СтрШаблон("curl -X GET 'https://people.googleapis.com/v1/people:searchContacts?query=test&readMask=names,emailAddresses' -H 'Authorization:Bearer %1,' -H 'Content-Type:application/x-www-form-urlencoded'", AccessToken); //	не возвращает
	
	Ответ = Авито.CURL_HttpResponse(кмд);	
	
	Если Ответ.КодСостояния <> 200 Тогда
		Сообщить(СтрШаблон("Ошибка: Ответ.КодСостояния = %1", Ответ.КодСостояния));
		ЗаписьЖурналаРегистрации("ПолучиДанные()", УровеньЖурналаРегистрации.Ошибка, ,кмд, "Http response code <> 200");
		Возврат
	КонецЕсли;  
	
	json = Ответ.ПолучитьТелоКакСтроку(); //Пример ответа: {"range": "Sheet2!A1",  "majorDimension": "ROWS", "values": [["373"]]}	
	
	Сообщить(json);
		
	Об = Авито.ПрочитатьЗначениеJSON(json);
		
	Если Об.values[0].Количество()= 0 Тогда
		Возврат
	КонецЕсли;
	
	Данные = Об.values[0];
	Sheet1_КоличествоСтрок = Число(Данные[0]);
	
	Если Число(Sheet1_КоличествоСтрок) = 0 Тогда
		Возврат;
	КонецЕсли;
	
	//Чтение Sheet1
	//----------------
	Sheet1_КоличествоСтрок = СтрЗаменить(Sheet1_КоличествоСтрок, Символ(160), "");  // Если былло "1 153" то получим "1153"
		
	//Прочитай диапазон из spreasheet
	//---------------------------------
	кмд   = СтрШаблон("curl -X GET 'https://sheets.googleapis.com/v4/spreadsheets/%1/values/Sheet1!A1:F%2'  -H 'Authorization:Bearer %3,' -H 'Content-Type:application/x-www-form-urlencoded'", spreadsheetId,Sheet1_КоличествоСтрок, AccessToken);
	Ответ = Авито.CURL_HttpResponse(кмд);

	Если Ответ.КодСостояния <> 200 Тогда
		Сообщить(СтрШаблон("Ошибка: Ответ.КодСостояния = %1", Ответ.КодСостояния));
		ЗаписьЖурналаРегистрации("ПолучиДанные()", УровеньЖурналаРегистрации.Ошибка, , кмд, "Http response code <> 200");
		Возврат
	КонецЕсли; 
	json = Ответ.ПолучитьТелоКакСтроку();

	ЗаписатьСтоимости(json);	

КонецПроцедуры

Функция ЗаписатьСтоимости(json)  
	Возврат "отмена";
	
	Доступно = ТипЗнч(json) = Тип("Строка") И СтрДлина(json)> 0;
		
	Данные = Авито.ПрочитатьЗначениеJSON(json);
	
	ТипСтр 		= Новый ОписаниеТипов("Строка");
	ТипЧисло	= Новый ОписаниеТипов("Число");
	
	ТЗ = Новый ТаблицаЗначений();
	ТЗ.Колонки.Добавить("Date", 			ТипСтр);
	ТЗ.Колонки.Добавить("CustomerName",		ТипСтр);
	ТЗ.Колонки.Добавить("CustomerID",		ТипСтр);	
	ТЗ.Колонки.Добавить("CampaignId", 		ТипСтр);
	ТЗ.Колонки.Добавить("Clicks",			ТипЧисло);
	ТЗ.Колонки.Добавить("Cost",				ТипЧисло);
	
	// это массив включающий массивы
	
	values = Данные.values;  
	Для Каждого Эл из values Цикл  // Эл это тоже массив 
		Период 			= Эл[0];
		АдвКлиентИмя 	= Эл[1]; // Имя клиента, не загружаем в регистр
		АдвКлиентИД		= Эл[2]; //CustomerID
		КомпанияИд		= Эл[3];
		Клики			= Эл[4];
		Стоимость 		= Эл[5];
		
		Стоимость	= Число(Стоимость);
		
		Если Стоимость = 0 Тогда
			Продолжить;
		КонецЕсли;
		
		Новая = ТЗ.Добавить();
		Новая["Date"] 			= Период;
		Новая["CustomerName"]	= АдвКлиентИмя;  // не загружается в регистр
		Новая["CustomerID"]		= АдвКлиентИД;	
		Новая["CampaignId"] 	= КомпанияИд;
		Новая["Clicks"] 		= Клики;
		Новая["Cost"] 			= Стоимость;
	КонецЦикла;
			
	Значения = Новый Массив();
		
	Для Каждого СтрокаТЗ Из ТЗ Цикл
		
		Date 	= СтрокаТЗ["Date"];		
		Период 	= ПрочитатьДатуJSON(Date, ФорматДатыJSON.ISO);
		
		УчетнаяЗапись	=	СтрокаТЗ["CustomerID"];
		ИдДомпании		=	СтрокаТЗ["CampaignId"];
		Клики			= 	Число(СтрокаТЗ["Clicks"]);
		Стоимость 		= 	Число(СтрокаТЗ["Cost"]);
		
		ИдКомпанииСсылка 	= Справочники.ИдентификаторыСтрокИнтернетЗаявок.УстановиИдентификаторСтроки(ИдДомпании,				"Google Adwords");
		СервисСсылка 		= Справочники.ИдентификаторыСтрокИнтернетЗаявок.УстановиИдентификаторСтроки("Google AdWords",	 	"Google Adwords");
		УчетнаяЗаписьСсылка = Справочники.ИдентификаторыСтрокИнтернетЗаявок.УстановиИдентификаторСтроки(УчетнаяЗапись, 			"Google Adwords");
		
	
		МЗ = РегистрыСведений.ИнтернетЗаявкиСтоимость.СоздатьМенеджерЗаписи();
		МЗ.ПериодЗаявки 	= Период;
		МЗ.ИдКомпании 		= ИдКомпанииСсылка; // CustomerID
		МЗ.Сервис 			= СервисСсылка;
		МЗ.УчетнаяЗапись 	= УчетнаяЗаписьСсылка;
		МЗ.Клики 			= Клики;
		МЗ.Стоимость 		= Стоимость;
		
		Попытка
			МЗ.Записать();
		Исключение
			Данные = "ПериодЗаявки = "+Период+"; ИдКомпании = "+ИдКомпанииСсылка+"; Сервис = "+ СервисСсылка+"; УчетнаяЗапись = "+УчетнаяЗаписьСсылка+"; Клики = "+Клики+"; Стоимость = "+Стоимость;
			ОбслуживаниеСервер.ЗарегистрироватьСобытие("ЗаписатьСтоимости()", УровеньЖурналаРегистрации.Ошибка, , Данные, ПодробноеПредставлениеОшибки(ИнформацияОбОшибке()));
			Возврат "Ошикба: неудалось записать данные в регистр сведений";
		КонецПопытки;
		
	КонецЦикла;
	
	Возврат "ок";

КонецФункции

Функция ПолучиьПодписьSHA256RSA(ХешДвоичный, ПараметрыСертификатаСтруктура)
// заимствована из обработки Инфостарт GetGooglAPIAccessToken2LO.epf	(https://infostart.ru/public/805071)

	ХешХексСтрока = ПолучитьHexСтрокуИзДвоичныхДанных(ХешДвоичный);
	
	// PKCS #1 v2.2: RSA Cryptography Standard, 9.2 EMSA-PKCS1-v1_5
	// перед подписанием хеш дополняется данными
	// EM  = 0x00 || 0x01 ||PS  || 0x00 ||T
	// T SHA-256:  (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H
	ЕМ = "0001" + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"+
	"00" + "3031300D060960864801650304020105000420" + ХешХексСтрока; 
	
	ХешХексСтрока = ЕМ;
  	хешчисло = ЧислоИзШестнадцатеричнойСтроки("0x"+ХешХексСтрока);
	
	СтрукСерт = ПараметрыСертификатаСтруктура;	
	dP 			= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.DP);
	p 			= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.P);
	dQ	 		= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.DQ);
	q 			= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.Q);
	qInv 		= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.InverseQ);
	Exponent 	= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.Exponent); //открытый параметр ключа
	Modulus 	= ЧислоИзШестнадцатеричнойСтроки("0x"+СтрукСерт.Modulus); //открытый параметр ключа
	
	//s1 = pow(хешчисло,DP_Число)% P_Число;//переполнение десятичной арифметики
	
	// ↓ вычисление подписи по ускоренному алгоритму
	s1 = ВозведениеВСтепеньПоМодулю (хешчисло, dP, p);
	s2 = ВозведениеВСтепеньПоМодулю (хешчисло, dQ, q);
	Если s1>s2 Тогда
		h = ((s1-s2)*qInv)%p
	Иначе
		h = ((s1-s2+p)*qInv)%p
	КонецЕсли;
	s = s2 + q*h; //подпись - число
	// ↑
	
	ПроверкаПодписиЧисло = ВозведениеВСтепеньПоМодулю (s, Exponent, Modulus);
	подписьВерна = (ПроверкаПодписиЧисло = хешчисло);
	Сообщить ("Подпись верна:" + подписьВерна); 
	
	Возврат ДвоичныеИзЧисла(s)
	
КонецФункции

Функция ВозведениеВСтепеньПоМодулю (Основание, Степень, Модуль)
	// заимствована из обработки Инфостарт GetGooglAPIAccessToken2LO.epf	(https://infostart.ru/public/805071)

	// Двоичное представление степени переведем в массив нулей и единиц в обратном порядке
	МассивЕдиниц = Новый Массив;
	Значение = Степень;
    Пока Значение>0 цикл
        Остат = Значение%2;
		МассивЕдиниц.Добавить(Остат);
        Значение = (Значение-Остат)/2;
	КонецЦикла;
	
	//Основание переведем в массив по хитрому правилу
	МассивИзОснования = Новый Массив;
	Для сч=0 по МассивЕдиниц.ВГраница() Цикл
		Если сч = 0 тогда
			МассивИзОснования.Добавить(Основание);
		Иначе
			МассивИзОснования.Добавить(pow(МассивИзОснования[сч-1],2)%Модуль);
		КонецЕсли;
	КонецЦикла;
	
	//Вычислим произведение степеней
	Произведение = 1;
	Для сч=0 по МассивЕдиниц.ВГраница() Цикл
		Произведение = Произведение * pow(МассивИзОснования[сч],МассивЕдиниц[сч]);
	КонецЦикла;
	
	Возврат Произведение%Модуль;
	
КонецФункции

Функция ДвоичныеИзЧисла(знач мЧисло)
	// заимствована из обработки Инфостарт GetGooglAPIAccessToken2LO.epf	(https://infostart.ru/public/805071)	
	
	МассивЧиселБайт = Новый Массив;
	Пока мЧисло>0 Цикл
		ТекущийБайт = мЧисло%256;
		МассивЧиселБайт.Добавить(ТекущийБайт);
		мЧисло = (мЧисло - ТекущийБайт)/256;
	КонецЦикла;
	РазмерБайт = МассивЧиселБайт.Количество();
	Буфер = Новый БуферДвоичныхДанных(РазмерБайт);
	Для сч = 0 по РазмерБайт-1 Цикл
		Буфер.Установить(РазмерБайт-1-сч, МассивЧиселБайт[сч]);
	КонецЦикла;

	Возврат ПолучитьДвоичныеДанныеИзБуфераДвоичныхДанных(Буфер);
	
КонецФункции

#Область Инфостарт

Функция ПолучитьСтруктуруСертификата()
	// заимствована из обработки Инфостарт GetGooglAPIAccessToken2LO.epf	(https://infostart.ru/public/805071)
	
	//Прочитай данные из текстового макета
	//МакетПодписиДвоичный = ПолучитьМакет("ФайлЗакрытогоКлюча_json");    //=>
	
	Парам = Новый Структура("Файл_JSON_закрытого_ключа_сервисного_Google_аккаунта_notify");
	РегистрыСведений.УчетнаяПолитика.Получи(Парам);
	Если Не ЗначениеЗаполнено(Парам.Файл_JSON_закрытого_ключа_сервисного_Google_аккаунта_notify) Тогда
		Возврат Неопределено;
	КонецЕсли;     	
	МакетПодписиДвоичный = ПолучитьДвоичныеДанныеИзСтроки(Парам.Файл_JSON_закрытого_ключа_сервисного_Google_аккаунта_notify);

	СтруктураСертификата = Новый Структура;
	жсон = Новый ЧтениеJSON;
	жсон.УстановитьСтроку(ПолучитьСтрокуИзДвоичныхДанных(МакетПодписиДвоичный));
	Пока жсон.Прочитать() Цикл
		Если жсон.ТипТекущегоЗначения = ТипЗначенияJSON.ИмяСвойства Тогда
			ИмяСвойства = жсон.ТекущееЗначение;
			жсон.Прочитать();
			ЗначениеСвойства =  жсон.ТекущееЗначение;
			СтруктураСертификата.Вставить(ИмяСвойства, ЗначениеСвойства);
		КонецЕсли;
	КонецЦикла;
	РасшаритьДляЕмейла = СтруктураСертификата.client_email;
	
	КлючСтрока = СтруктураСертификата.private_key;
	КлючСтрока = СтрЗаменить(КлючСтрока,"-----BEGIN PRIVATE KEY-----","");
	КлючСтрока = СтрЗаменить(КлючСтрока,"-----END PRIVATE KEY-----","");
	ХексСтрокаКлюча = ПолучитьHexСтрокуИзДвоичныхДанных(Base64Значение(КлючСтрока));
	Тэги = Новый Соответствие;
	Тэги.Вставить("30","SEQUENCE");
	Тэги.Вставить("02","INTEGER");
	Тэги.Вставить("06","OBJECT IDENTIFIER");
	Тэги.Вставить("04","OCTET STRING");
	Тэги.Вставить("05","NULL");
	
	ДлинаАдресаОдинБайт = "81";
	ДлинаАдресаДваБайта = "82";
	
	парс = Новый ДеревоЗначений;
	парс.Колонки.Добавить("Класс",Новый ОписаниеТипов("Строка",,,,Новый КвалификаторыСтроки(2)));
	парс.Колонки.Добавить("ИмяКласса",Новый ОписаниеТипов("Строка"));
	парс.Колонки.Добавить("ПредбайтДлины",Новый ОписаниеТипов("Строка",,,,Новый КвалификаторыСтроки(2)));
	парс.Колонки.Добавить("БайтДлины",Новый ОписаниеТипов("Строка",,,,Новый КвалификаторыСтроки(4)));
	парс.Колонки.Добавить("ДлинаЧисло", Новый ОписаниеТипов("Число",,,Новый КвалификаторыЧисла(10,0)));
	парс.Колонки.Добавить("Значение",Новый ОписаниеТипов("Строка"));
	
	СтрокаOCTET_STRING = Неопределено; //в октетстринг лежит RSAPrivateKey по RFC 3447
	ПарсХекс(парс,ХексСтрокаКлюча, СтрокаOCTET_STRING);
	
	RSAPrivateKey_SEQUENCE = СтрокаOCTET_STRING.Строки[0];
	// единственный элемент внутри OCTET_STRING, является RSAPrivateKey ::= SEQUENCE {...
	PKey_SEQUENCE_fields = RSAPrivateKey_SEQUENCE.Строки;
	
	//PKey_SEQUENCE_fields[0] - version не нужна
	СтруктураСертификата.Вставить("Modulus",	PKey_SEQUENCE_fields[1].Значение);
	СтруктураСертификата.Вставить("Exponent",	PKey_SEQUENCE_fields[2].Значение);
	СтруктураСертификата.Вставить("D",			PKey_SEQUENCE_fields[3].Значение);
	СтруктураСертификата.Вставить("P",			PKey_SEQUENCE_fields[4].Значение);
	СтруктураСертификата.Вставить("Q",			PKey_SEQUENCE_fields[5].Значение);
	СтруктураСертификата.Вставить("DP",			PKey_SEQUENCE_fields[6].Значение);
	СтруктураСертификата.Вставить("DQ",			PKey_SEQUENCE_fields[7].Значение);
	СтруктураСертификата.Вставить("InverseQ",	PKey_SEQUENCE_fields[8].Значение);
	
	Возврат СтруктураСертификата;
	
	//RFC 3447
   // A.1.2 RSA private key syntax

   //An RSA private key should be represented with the ASN.1 type
   //RSAPrivateKey:

   //   RSAPrivateKey ::= SEQUENCE {
   //  0     version           Version,
   //  1     modulus           INTEGER,  -- n
   //  2     publicExponent    INTEGER,  -- e
   //  3     privateExponent   INTEGER,  -- d
   //  4     prime1            INTEGER,  -- p
   //  5     prime2            INTEGER,  -- q
   //  6     exponent1         INTEGER,  -- d mod (p-1)
   //  7     exponent2         INTEGER,  -- d mod (q-1)
   //  8     coefficient       INTEGER,  -- (inverse of q) mod p
   //  9     otherPrimeInfos   OtherPrimeInfos OPTIONAL
   //   }

   //The fields of type RSAPrivateKey have the following meanings:

   // * version is the version number, for compatibility with future revisions of this document.  It shall be 0 for this version of the document, unless multi-prime is used, in which case it shall be 1.
   // * modulus is the RSA modulus n.
   // * publicExponent is the RSA public exponent e.
   // * privateExponent is the RSA private exponent d.
   // * prime1 is the prime factor p of n.
   // * prime2 is the prime factor q of n.
   // * exponent1 is d mod (p - 1).
   // * exponent2 is d mod (q - 1).
   // * coefficient is the CRT coefficient q^(-1) mod p.
   // * otherPrimeInfos contains the information for the additional primes r_3, ..., r_u, in order.  It shall be omitted if version is 0 and shall contain at least one instance of OtherPrimeInfo if version is 1.
	
КонецФункции

Процедура ПарсХекс(Родитель, ХексСтрокаКлюча, СтрокаOCTET_STRING)	
	// заимствована из обработки Инфостарт GetGooglAPIAccessToken2LO.epf	(https://infostart.ru/public/805071)

	Тэги = Новый Соответствие;
	Тэги.Вставить("30","SEQUENCE");
	Тэги.Вставить("02","INTEGER");
	Тэги.Вставить("06","OBJECT IDENTIFIER");
	Тэги.Вставить("04","OCTET STRING");
	Тэги.Вставить("05","NULL");
	
	Позиция = 1;
	//Родитель = парс;
	Пока Позиция < СтрДлина(ХексСтрокаКлюча) Цикл
		сПарс = Родитель.Строки.Добавить();
		
		сПарс.Класс = Сред(ХексСтрокаКлюча, Позиция, 2);
		Позиция = Позиция + 2;
		сПарс.ИмяКласса = Тэги.Получить(сПарс.Класс);
		
		байт = Сред(ХексСтрокаКлюча, Позиция, 2);
		Если байт = "81" или байт = "82" Тогда
			сПарс.ПредбайтДлины = байт;
			Позиция = Позиция + 2;
			
			КолвоБайтАдресации = Число(байт) - 80;
			сПарс.БайтДлины = Сред(ХексСтрокаКлюча, Позиция, 2 * КолвоБайтАдресации);
			Позиция = Позиция + 2 * КолвоБайтАдресации;
			сПарс.ДлинаЧисло = ЧислоИзШестнадцатеричнойСтроки("0x"+сПарс.БайтДлины);
			
			сПарс.Значение = Сред(ХексСтрокаКлюча, Позиция, 2 * сПарс.ДлинаЧисло);
			Позиция = Позиция + 2 * сПарс.ДлинаЧисло;
			//последнюю позицию сдвинем/несдвинем после Если
			
		Иначе
			сПарс.ПредбайтДлины = ""; //отсутствует
			
			сПарс.БайтДлины = Сред(ХексСтрокаКлюча, Позиция, 2);
			Позиция = Позиция + 2;
			сПарс.ДлинаЧисло = ЧислоИзШестнадцатеричнойСтроки("0x"+сПарс.БайтДлины);
			
			сПарс.Значение = Сред(ХексСтрокаКлюча, Позиция, 2 * сПарс.ДлинаЧисло);
			Позиция = Позиция + 2 * сПарс.ДлинаЧисло;

		КонецЕсли;
		
		Если сПарс.ИмяКласса = "OCTET STRING" Тогда
			СтрокаOCTET_STRING = сПарс;
		КонецЕсли;
		
		Если сПарс.ИмяКласса = "SEQUENCE" или сПарс.ИмяКласса = "OCTET STRING" Тогда
			// эти классы содержат подклассы, разбираем подветки рекурсивно
			ПарсХекс(сПарс, сПарс.Значение, СтрокаOCTET_STRING)
		КонецЕсли;
		
		
	КонецЦикла;
	
КонецПроцедуры
#КонецОбласти

#Область ПреобразованияТипов

//&НаСервереБезКонтекста
Функция Str2Binary(Стр="Hello world", Кодировка="UTF-8")
	// Преобразует строку любой кодовой страницы в двоичные данные	
	
	 Рез = ПолучитьДвоичныеДанныеИзСтроки(Стр, Кодировка);
	 Возврат Рез;
 КонецФункции
 
 //&НаСервереБезКонтекста
Функция Binary2Base64UrlStr(ДвоичнДанные = Неопределено)
	//Преобразует двоичные данные в строку, закодированную в формат Base64URL - т.е. строку, закодированную в Base64
	// в которой символы + и / заменяются, соответственно, на - и _ (RFC 3548, раздел 4). 

	Если ТипЗнч(ДвоичнДанные) <> Тип("ДвоичныеДанные") Тогда
		Возврат ""
	КонецЕсли;
	
	Base64Стр = Base64Строка(ДвоичнДанные);
	Base64Стр = стрЗаменить(Base64Стр, "+", "-");
	Base64Стр = стрЗаменить(Base64Стр, "/", "_");
	Base64Стр = стрЗаменить(Base64Стр, Символы.ВК, "");
	Base64Стр = стрЗаменить(Base64Стр, Символы.ПС, "");
	
	Если Прав(Base64Стр, 2) = "==" Тогда
		Base64Стр = Лев(Base64Стр,СтрДлина(Base64Стр)-2);
		
	ИначеЕсли Прав(Base64Стр, 1) = "=" Тогда
		Base64Стр = Лев(Base64Стр,СтрДлина(Base64Стр)-1);
	КонецЕсли;
	
	Возврат Base64Стр;
	
КонецФункции

#КонецОбласти
 
 
