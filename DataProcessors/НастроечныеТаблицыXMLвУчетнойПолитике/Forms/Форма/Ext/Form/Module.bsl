&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	
	Если ЗначениеЗаполнено(ЭтаФорма.Параметры.РегистрСведений) Тогда
		ЭтаФорма.Объект.РегистрСведений = ЭтаФорма.Параметры.РегистрСведений;
	КонецЕсли;
	
	Если ЗначениеЗаполнено(ЭтаФорма.Параметры.Измерение) Тогда
		ЭтаФорма.Объект.Измерение = ЭтаФорма.Параметры.Измерение;
	КонецЕсли;
	
	Если ЗначениеЗаполнено(ЭтаФорма.Параметры.Ресурс) Тогда
		ЭтаФорма.Объект.Ресурс = ЭтаФорма.Параметры.Ресурс;
	КонецЕсли;
	
	Если ЗначениеЗаполнено(ЭтаФорма.Параметры.ЗначениеИзмерения) Тогда
		ЭтаФорма.Объект.ЗначениеИзмерения = ЭтаФорма.Параметры.ЗначениеИзмерения;
		
		//Если при вызове формы параметры заполнены, значит она вызвана не напрямую,
		// т.е. не предполагает изменение этих настроек, поэтому скроем все закладки, кроме "СтрДанные"
		
		ЭтаФорма.Элементы.СтрПараметрыТаблицы.Видимость = Ложь;
		ЭтаФорма.Элементы.СтрОтладкаСкрыть.Видимость	=Ложь;
	КонецЕсли;
	
	//Установи настройки по умолчанию
	//------------------------------------
	Об = РеквизитФормыВЗначение("Объект");                        
	Об.УстановитьНастройки();
	ЗначениеВРеквизитФормы(Об, "Объект");
	
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	ЗаполниТаблицу()
КонецПроцедуры


&НаСервере
Процедура ПрочитайСписокКолонокXMLиДанные()
	Об 		= РеквизитФормыВЗначение("Объект");
	
	Текст 	=  Об.ПолучиТекст();
	Об.Текст = Текст;
	
	Об.ЗаполниСписокXMLэлементовОписывающихСтруктуруТаблицы(Текст, Об.ИменаXMLЭлементов, 10);
	
	Об.Прочитать(Текст);
	

	ЗначениеВРеквизитФормы(Об, "Объект");
	
КонецПроцедуры

&НаКлиенте
Процедура ЗаполниТаблицу(Команда=Неопределено)
	ПрочитайСписокКолонокXMLиДанные();
	
	// Вместо заголовков колонок "Колонка1", "Колонка" используй имена колонок из xml
	//--------------------------------------------------------------------------------
	Для Каждого Элем Из ЭтаФорма.Элементы Цикл
		
		Если Элем.Родитель=ЭтаФорма Тогда
			Продолжить;
		КонецЕсли;
		
		Если ТипЗнч(Элем) <> Тип("ПолеФормы") Тогда
			Продолжить;
		КонецЕсли;
			
		Если СтрНайти(Элем.Имя, "ТЗКолонка")=0 Тогда 
			Продолжить;
		КонецЕсли;
		Если СтрНайти(Элем.Имя, "КонтекстноеМеню")>0 Тогда 
			Продолжить;
		КонецЕсли;

		
		НомерКолонки=Число(Прав(Элем.Имя, СтрДлина(Элем.Имя)-СтрДлина("ТЗКолонка")));
		xmlИмяКолонки = ЭтаФорма.Объект.ИменаXMLЭлементов.Получить(НомерКолонки).Значение;
		Если xmlИмяКолонки = "" Тогда
			Элем.Видимость = Ложь;
		Иначе
			Элем.Заголовок = xmlИмяКолонки;
		КонецЕсли;
	КонецЦикла;
	
	//В качестве заголовка закладки отобрази имя настроечной таблицы
	//---------------------------------------------------------------
	ЭтаФорма.Элементы["СтрДанные"].Заголовок ="Таблица: "+ ЭтаФорма.Объект.ЗначениеИзмерения;

КонецПроцедуры


&НаСервере
Процедура ЗаписатьНаСервере()
	Об = РеквизитФормыВЗначение("Объект");
 	Об.Записать();	
КонецПроцедуры

&НаКлиенте
Процедура Записать(Команда)
	ЗаписатьНаСервере();	
КонецПроцедуры

&НаКлиенте
Процедура СтрцыПриСменеСтраницы(Элемент, ТекущаяСтраница)
	Если ТекущаяСтраница.Имя="СтрДанные" Тогда
		ЗаполниТаблицу();
	КонецЕсли;
КонецПроцедуры
