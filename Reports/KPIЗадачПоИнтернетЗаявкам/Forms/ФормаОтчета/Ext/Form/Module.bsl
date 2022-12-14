
&НаСервере
Функция РезультатОбработкаРасшифровкиНаСервере(Расшифровка)
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = Ложь;
	
	//Получи расшифровку отчета из временного хранилища, адрес расшифровки содержится в свойстве формы 
	РасшифровкаОтчета = ПолучитьИзВременногоХранилища(ЭтаФорма.ДанныеРасшифровки);
	
	//Получи параметры данных отчета из ДанныеРасшифровкиКД.Настройки
	ПарамКД = Новый ПараметрКомпоновкиДанных("Период");
	ЗначПарамКД = РасшифровкаОтчета.Настройки.ПараметрыДанных.НайтиЗначениеПараметра(ПарамКД);
	
	ДатаПостановкиНачало = Дата(1,1,1);
	Если ЗначПарамКД = Неопределено Тогда
		ЗаписьЖурналаРегистрации("Обработка расшифровки", УровеньЖурналаРегистрации.Ошибка, Метаданные.Отчеты.KPIЗадачПоИнтернетЗаявкам, , "Ошибка поиска параметра ДатаПостановкиНачало"); 
		Возврат ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ;
	Иначе 
		Период = ЗначПарамКД.Значение;
	КонецЕсли;
	
	//Получи имя показателя KPI для расшифровки  из ДанныеРасшифровкиКД.Элементы
	ЭлементыРасшКД	 	= РасшифровкаОтчета.Элементы;
	ЭлементРасшКДПоля 	= ЭлементыРасшКД[Расшифровка];
	ЗначенияПолейРасшКД = ЭлементРасшКДПоля.ПолучитьПоля();
	ЗначениеПоляРасшКД 	= ЗначенияПолейРасшКД[0];
	
	Если ЗначениеПоляРасшКД.Поле = "ИмяПоказателя" Тогда
		
		//Если 	  ЗначениеПоляРасшКД.Значение = "Количество задач всего" Тогда				
		//ИначеЕсли ЗначениеПоляРасшКД.Значение = "Количество успешных переключений" Тогда
		//ИначеЕсли ЗначениеПоляРасшКД.Значение = "Количество закрытых вручную" Тогда
		//ИначеЕсли ЗначениеПоляРасшКД.Значение = "Доля успешных закрытий" Тогда
		//ИначеЕсли ЗначениеПоляРасшКД.Значение = "Количество успешных переключений не обработанных в срок" Тогда
		//КонецЕсли;
		
		НастройкиКД_ТекущегоОтчета = ЭтаФорма.Отчет.КомпоновщикНастроек.ПолучитьНастройки();
		АдресНастроекКД_ТекущегоОтчета = ПоместитьВоВременноеХранилище(НастройкиКД_ТекущегоОтчета);
		
		Парам = Новый Структура();
		Парам.Вставить("АдресНастроекКДМастерОтчета",АдресНастроекКД_ТекущегоОтчета);
		Парам.Вставить("ИмяПоказателяКРасшифровке", ЗначениеПоляРасшКД.Значение);
		Парам.Вставить("ОтборПричинаРучногоЗакрытияСПАМ", ""); //значение по умолчанию
		
		// Если расфшировывается показатель количество задач закрытых вручную по причине СПАМ
		//тогда нужно передать в отбор значение строкового фильтра
		Если ЗначениеПоляРасшКД.Значение = "Количество закрытых вручную по причине СПАМ" Тогда
			ПарамКД = Новый ПараметрКомпоновкиДанных("Спам");
			ЗначПарамКД = РасшифровкаОтчета.Настройки.ПараметрыДанных.НайтиЗначениеПараметра(ПарамКД);

			Парам.Вставить("ОтборПричинаРучногоЗакрытияСПАМ", ПарамКД);
		КонецЕсли;
		
		ДляОткрытьФормуНаКлиенте = Новый Структура();
		ДляОткрытьФормуНаКлиенте.Вставить("ИмяФормы", "Отчет.ЗадачиПоИнтернетЗаявкам.Форма.ФормаОтчета");
		ДляОткрытьФормуНаКлиенте.Вставить("ПараметрыФормы", Парам);
		
		Возврат ДляОткрытьФормуНаКлиенте;

	КонецЕсли;
	
	
КонецФункции

&НаКлиенте
Процедура РезультатОбработкаРасшифровки(Элемент, Расшифровка, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
	Рез = РезультатОбработкаРасшифровкиНаСервере(Расшифровка);
	
	Если ТипЗнч(Рез) <> Тип("Структура") Тогда
		Возврат
	КонецЕсли;
	
	ОткрытьФорму(Рез.ИмяФормы, Рез.ПараметрыФормы);
КонецПроцедуры
