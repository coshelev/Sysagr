﻿&НаКлиенте
Процедура АвторизацияШаг1_ПолучиAuthCode(Команда)
	//Первый этап авторизации: получение кода доступа: сработает на тонком и вэб-клиентах. Сформируй GET-запрос
	//---------------------------------------------------------------------------------------------------------
	
	client_id = "928904804703-4b6iqv0nckkrltnf6r9pr2fj6mfg73d0.apps.googleusercontent.com";	
	
    //scope = "https://www.googleapis.com/auth/calendar + https://www.googleapis.com/auth/userinfo.email"; // Просмотр и изменение календаря и почты
    //scope = "https://www.googleapis.com/auth/contacts"; 		//Просмотр и изменение контактов
    //scope = "https://www.googleapis.com/auth/calendar"; 		//Просмотр и изменение календаря
    scope = "https://www.googleapis.com/auth/spreadsheets"; 	//Просмотр и изменение таблиц на Google Диске

	//ПолныйАдресАвторизации = АдресАвторизации + ЧастьЗапроса;
	URL = СтрШаблон("https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=%1&redirect_uri=urn:ietf:wg:oauth:2.0:oob&access_type=offline&scope=%2",client_id,  scope); 
	GotoURL(URL);
КонецПроцедуры

&НаКлиенте
Процедура АвторизацияШаг2ПолучиТокены()
	//Второй этап авторизации для тонкого клиента
	//============================================
	
	//Вариант 1:  для web-клиента код нужно исполнять на сервере
	//=============================================================	
	//ТекСреда = ПолучитьТекущуюСредуВыполнения();
	//Сооб = Новый СообщениеПользователю();
	//Сооб.Текст = "ТекСреда"+ТекСреда;
	//Сооб.Сообщить();
	//
	//Если ТекСреда = "Веб-клиент" Тогда
	//		Строка = АвторизацияШаг2ПолучиТокены_НаСервере();
	//		Сообщить(Строка);
	//	Возврат;
	//КонецЕсли;
	
	//Вариант 2: на тонком клиенте
	//==============================================================
	
	//Второй этап авторизации: получение access_token (живет 1 час) и refresh_token (для обновления после истечения часа)
	//-------------------------------------------------------------------------------------------------------------------	
	Если ЭтаФорма.AuthCode = "" Тогда
		Возврат
	КонецЕсли;

	client_id 		=	"928904804703-4b6iqv0nckkrltnf6r9pr2fj6mfg73d0.apps.googleusercontent.com";
	client_secret 	=	"8w0zYR3wTpMb3BoAtJGdGtPZ";
	
	Сервер =  "accounts.google.com";
	Ресурс = "/o/oauth2/token";
	
	СтрокаЗапроса = "client_id=" 					 	+ client_id + 
					"&client_secret=" 					+ client_secret + 
					"&grant_type=authorization_code" 	+
					"&code="							+ ЭтаФорма.AuthCode + 
					"&redirect_uri=urn:ietf:wg:oauth:2.0:oob";

	HttpСоед = Новый HTTPСоединение(Сервер,443,,,,,Новый ЗащищенноеСоединениеOpenSSL);
	HttpЗапрос = Новый HTTPЗапрос();
	HttpЗапрос.АдресРесурса = "/o/oauth2/token";
	HttpЗапрос.Заголовки.Вставить("Content-Type","application/x-www-form-urlencoded");
	HttpЗапрос.УстановитьТелоИзСтроки(СтрокаЗапроса);
	
	Ответ = HttpСоед.ВызватьHTTPМетод("POST",HttpЗапрос);
	
	//Если некоректный ответ, тогда возврат
	//-------------------------------------
	Если Ответ.КодСостояния <> 200 Тогда
		Возврат 
	КонецЕсли;		
	Строка = Ответ.ПолучитьТелоКакСтроку();
	
	Чтение = Новый ЧтениеJSON();
	Чтение.УстановитьСтроку(Строка);
	Фабрика = ПрочитатьJSON(Чтение);	
	Чтение.Закрыть();
	
	Токен		 	= Фабрика.access_token;  	// живет 1 час, нужно получать новый с помощью refresh_token
	ТокенОбновления = Фабрика.refresh_token;
	
	ЭтаФорма.AccessToken	= Фабрика.access_token;
	ЭтаФорма.RefreshToken 	= Фабрика.refresh_token;
	
	//Второй этап завершен авторизации завершен
	
	//Обработка данных один (первый раз)
	//-----------------------------------
	ПолучиДанные_НаКлиенте();

	// Получение нового access token примерно каждый час
	//--------------------------------------------------
	//Интервал50минутВСекундах = 50*60;	
	//ПодключитьОбработчикОжидания("ОбновиAccessToken_НаКлиенте", Интервал50минутВСекундах); 
	
	// Обработка данных через каждые 10 минут
	//----------------------------------------
	//ПодключитьОбработчикОжидания("ПолучиДанные_НаКлиенте", 600);
		
КонецПроцедуры

&НаКлиенте
Процедура ОбновиAccessToken_НаКлиенте()

	client_id 		=	"928904804703-4b6iqv0nckkrltnf6r9pr2fj6mfg73d0.apps.googleusercontent.com";
	client_secret 	=	"8w0zYR3wTpMb3BoAtJGdGtPZ";
	
	Сервер =  "accounts.google.com";
	Ресурс = "/o/oauth2/token";
	
	СтрокаЗапроса = "refresh_token="			+ ЭтаФорма.RefreshToken +
					"client_id="				+ client_id + 
					"&client_secret="			+ client_secret + 
					"&grant_type=refresh_token";

	HttpСоед = Новый HTTPСоединение(Сервер,443,,,,,Новый ЗащищенноеСоединениеOpenSSL);
	HttpЗапрос = Новый HTTPЗапрос();
	HttpЗапрос.АдресРесурса = "/o/oauth2/token";
	HttpЗапрос.Заголовки.Вставить("Content-Type","application/x-www-form-urlencoded");
	HttpЗапрос.УстановитьТелоИзСтроки(СтрокаЗапроса);

	//ИмяТемпФайла = ПолучитьИмяВременногоФайла();
	
	Ответ = HttpСоед.ВызватьHTTPМетод("POST",HttpЗапрос);
	
	Если Ответ.КодСостояния <> 200 Тогда
		Возврат 
	КонецЕсли;		
	Строка = Ответ.ПолучитьТелоКакСтроку();
	
	Чтение = Новый ЧтениеJSON();
	Чтение.УстановитьСтроку(Строка);
	Фабрика = ПрочитатьJSON(Чтение);	
	Чтение.Закрыть();
	
	ЭтаФорма.Токен		 	= Фабрика.access_token;  	// живет 1 час, нужно получать новый с помощью refresh_token

	
КонецПроцедуры

&НаКлиенте
Процедура ПолучиДанные_НаКлиенте()
	//Собственно получение данных
	//===========================
		
	Сервер = "sheets.googleapis.com";	

	//Spreadsheet ID (см. https://developers.google.com/sheets/api/guides/concepts#spreadsheet_id)
	//Every API method requires a spreadsheetId parameter which is used to identify which spreadsheet is to be accessed or altered. 
	//This ID is the value between the "/d/" and the "/edit" in the URL of your spreadsheet. 
	//For example, consider the following URL that references a Google Sheets spreadsheet:
	//https://docs.google.com/spreadsheets/d/1qpyC0XzvTcKT6EISywvqESX3A0MwQoFDE8p-Bll4hps/edit#gid=0
	//The ID of this spreadsheet is 1qpyC0XzvTcKT6EISywvqESX3A0MwQoFDE8p-Bll4hps.
	//--------------------------------------------------------------------------------------------------------------------------------
	
	spreadsheetId="1rMYnx6YTp6qnssSOg-rU64UczMZ3cFdxWVsMNf-uAtw"; 		//книга notifyme348@gmail.com_SysAgr_for_Adwords из аккаунта notifyme348@gmail.com 				- работает
	
	//Чтение Sheet2 - количества заполненных строк на листе Sheet1
	//==============================================================

	//АдресРесурса =  "v4/spreadsheets/"+spreadsheetId+"/values/Sheet1!A1:E100";
	АдресРесурса =  "v4/spreadsheets/"+spreadsheetId+"/values/Sheet2!A1:A1";
	
	//Чтение работает только по Get (см. https://developers.google.com/sheets/api/guides/values)
	//--------------------------------------------------------------------------------------------
	ВариантАвторизации = 2;  // использовать только для отладки!
	
	//Есть два варианта авторизации при использовании с использованием OAuth 2.0 token (см. https://developers.google.com/sheets/api/query-parameters) 
	//1. Using the access_token query parameter like this: ?access_token=oauth2-token
	//--------------------------------------------------------------------------------------------------------
	Если ВариантАвторизации = 1 Тогда
		//этот вариант можно попробовать в браузере https://sheets.googleapis.com/v4/spreadsheets/spreadsheetId/values/Sheet1!A1:D5?access_token="+Токен
	    //---------------------------------------------------------------------------------------
		ПерейтиПоНавигационнойСсылке("https://"+Сервер+"/"+АдресРесурса+"?access_token="+ЭтаФорма.AccessToken);
		Возврат;
	КонецЕсли;
	
	//2. Using the HTTP Authorization header like this: Authorization: Bearer oauth2-token
	//------------------------------------------------------------------------------------
	// этот вариант в браузере не проверишь
	Сервер = "sheets.googleapis.com";	
	HttpСоед = Новый HTTPСоединение(Сервер,443,,,,,Новый ЗащищенноеСоединениеOpenSSL);
		
	HttpЗапрос = Новый HTTPЗапрос();
	HttpЗапрос.АдресРесурса =  АдресРесурса;
	HttpЗапрос.Заголовки.Вставить("Authorization","Bearer " + ЭтаФорма.AccessToken);
	HttpЗапрос.Заголовки.Вставить("Content-Type", "application/x-www-form-urlencoded");
		
	//Прочитай диапазон из spreasheet
	//------------------------------------------
	Ответ = HttpСоед.ВызватьHTTPМетод("GET",HttpЗапрос);
	
	//Если некоректный ответ, тогда возврат
	//-------------------------------------
	Если Ответ.КодСостояния <> 200 Тогда
		Сообщить("Ответ.КодСостояния = "+Ответ.КодСостояния);
		Возврат
	КонецЕсли;
	json = Ответ.ПолучитьТелоКакСтроку(); //Пример ответа: {"range": "Sheet2!A1",  "majorDimension": "ROWS", "values": [["373"]]}	
	//Сообщить(json);
	
	Чтение = Новый ЧтениеJSON();
	Чтение.УстановитьСтроку(json);
	Фабрика = ПрочитатьJSON(Чтение);	
	Чтение.Закрыть();
	
	Если Фабрика.values[0].Количество()= 0 Тогда
		Возврат
	КонецЕсли;
	
	Данные = Фабрика.values[0];
	Sheet1_КоличествоСтрок = Число(Данные[0]);
	
	Если Число(Sheet1_КоличествоСтрок) = 0 Тогда
		Возврат;
	КонецЕсли;
	
	//Чтение Sheet1
	//==============================================================================================
	Sheet1_КоличествоСтрок = СтрЗаменить(Sheet1_КоличествоСтрок, Символ(160), "");  // Если былло "1 153" то получим "1153"
	АдресРесурса =  "v4/spreadsheets/"+spreadsheetId+"/values/Sheet1!A1:F"+СокрЛП(Sheet1_КоличествоСтрок);
	
	Сервер = "sheets.googleapis.com";	
	HttpСоед = Новый HTTPСоединение(Сервер,443,,,,,Новый ЗащищенноеСоединениеOpenSSL);
	
	HttpЗапрос = Новый HTTPЗапрос();
	HttpЗапрос.АдресРесурса =  АдресРесурса;
	HttpЗапрос.Заголовки.Вставить("Authorization","Bearer " + ЭтаФорма.AccessToken);
	HttpЗапрос.Заголовки.Вставить("Content-Type", "application/x-www-form-urlencoded");
		
	//Прочитай диапазон из spreasheet
	//------------------------------------------
	Ответ = HttpСоед.ВызватьHTTPМетод("GET",HttpЗапрос);
	
	//Если некоректный ответ, тогда возврат
	//-------------------------------------
	Если Ответ.КодСостояния <> 200 Тогда
		Сообщить("Ответ.КодСостояния = "+Ответ.КодСостояния);
		Возврат
	КонецЕсли;
	json = Ответ.ПолучитьТелоКакСтроку();
	//Сообщить(json);
	
	ЗаписатьСтоимости(json);	

КонецПроцедуры

&НаСервере
Функция ЗаписатьСтоимости(json)   
	Возврат "отмена";
	
	Доступно = ТипЗнч(json) = Тип("Строка");
	Доступно = СтрДлина(json) И Доступно;
	
	Чтение = Новый ЧтениеJSON();
	Чтение.УстановитьСтроку(json);
	Данные = ПрочитатьJSON(Чтение);	
	Чтение.Закрыть();

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
			Комментарий = ОписаниеОшибки();
			ОбслуживаниеСервер.ЗарегистрироватьСобытие("ЗаписатьСтоимости()", УровеньЖурналаРегистрации.Ошибка, Метаданные.РегистрыСведений.ИнтернетЗаявкиСвойства, Данные, Комментарий);
			Возврат "Ошикба: неудалось записать данные в регистр сведений";
		КонецПопытки;
		
	КонецЦикла;
	
	Возврат "ок";

КонецФункции
