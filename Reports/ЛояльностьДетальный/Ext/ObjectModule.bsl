Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	
	СтандартнаяОбработка = Ложь;
	
	ПараметрыДанных = КомпоновщикНастроек.Настройки.ПараметрыДанных;
	ПараметрыДанных.УстановитьЗначениеПараметра("Начало", 		Период.ДатаНачала);
	ПараметрыДанных.УстановитьЗначениеПараметра("Окончание", 	Период.ДатаОкончания);
	
	//Сформируй главный запрос отчета
	//---------------------------------
	Запрос = Новый Запрос();
	Если ВыбранныйВариантОтчета = "а" Тогда
		Рез = ОбработкаОтчетов.ЗапросЛояльностиДетальный(Период.ДатаНачала, Период.ДатаОкончания, Число(ТипПериода));
		Если Рез.Пустой() Тогда
			Возврат;
		КонецЕсли;		 
	ИначеЕсли ВыбранныйВариантОтчета = "б" Тогда
	КонецЕсли;
	
	ВнешниеНаборыДанных = Новый Структура();
	ВнешниеНаборыДанных.Вставить("ТЗ", Рез);
	
	Если ВыбранныйВариантОтчета = "а" Тогда
		СКД = ПолучитьМакет("ПоказателиВИзмерении");	
	ИначеЕсли ВыбранныйВариантОтчета = "б" Тогда
		СКД = ПолучитьМакет("ПоказателиВРесурсахДетально");	
	КонецЕсли;
		
	Настройки = СКД.НастройкиПоУмолчанию;
	
	КомпоновщикМакета 			= Новый КомпоновщикМакетаКомпоновкиДанных();
	МакетКомпоновки 			= КомпоновщикМакета.Выполнить(СКД, Настройки, ДанныеРасшифровки);
	ПроцессорКомпоновкиДанных 	= Новый ПроцессорКомпоновкиДанных();
	ПроцессорКомпоновкиДанных.Инициализировать(МакетКомпоновки, ВнешниеНаборыДанных, ДанныеРасшифровки);
	 
	ПроцессорВывода = Новый ПроцессорВыводаРезультатаКомпоновкиДанныхВТабличныйДокумент();
	ПроцессорВывода.УстановитьДокумент(ДокументРезультат);
	ПроцессорВывода.Вывести(ПроцессорКомпоновкиДанных);	

КонецПроцедуры
