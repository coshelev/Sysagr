﻿
&НаКлиенте
Процедура РезультатОбработкаРасшифровки(Элемент, Расшифровка, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
	рез = РезультатОбработкаРасшифровкиНаСервере(Расшифровка);
	
	Если Не ЗначениеЗаполнено(Рез) Тогда
		Возврат
	КонецЕсли;
	
	Если ТипЗнч(Рез)<>Тип("Строка") Тогда
		Возврат;
	КонецЕсли;
	
	Если СтрНайти(Рез, "#", , 2) >1 Тогда
		Парам = Новый Структура();
		Парам.Вставить("Сигнатура", рез);
		Если Лев(Рез,1) = "0" Тогда
			ИмяОткрываемойФормы = "РегистрСведений.Звонки.Форма.ФормаВходящегоЧтение";
		Иначе
			ИмяОткрываемойФормы = "РегистрСведений.Звонки.Форма.ФормаИсходящегоЧтение";
		КонецЕсли;
		ОткрытьФорму(ИмяОткрываемойФормы, Парам);
        Возврат;
	КонецЕсли;
	
	Если СтрНайти(Рез, "@")>1 Тогда
		Парам = Новый Структура();
		Парам.Вставить("Сигнатура", рез);
		ОткрытьФорму("РегистрСведений.ПисьмаСодержание.ФормаЗаписи", Парам);
	КонецЕсли;
	
КонецПроцедуры

&НаСервере
Функция РезультатОбработкаРасшифровкиНаСервере(Расшифровка)
	РасшифровкаОтчета = ПолучитьИзВременногоХранилища(ЭтаФорма.ДанныеРасшифровки);
	ЭлементыРасшифровки = РасшифровкаОтчета.Элементы;
	РасшифровкаЯчейки =  ЭлементыРасшифровки.Получить(Расшифровка);
	ЗначенияПолейРасш = РасшифровкаЯчейки.ПолучитьПоля();
	ЗначениеПоляРасш = ЗначенияПолейРасш.Получить(0);
	Возврат ЗначениеПоляРасш.Значение;
КонецФункции

&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
	Если Не ЗначениеЗаполнено(ЭтаФорма.Параметры.АдресНастроекКДМастерОтчета) Тогда
		Возврат
	КонецЕсли;
	НастройкиКДМастерОтчета = ПолучитьИзВременногоХранилища(ЭтаФорма.Параметры.АдресНастроекКДМастерОтчета);
		
	//Получи параметры данных отчета из ДанныеРасшифровкиКД.Настройки
	Период = Новый ПараметрКомпоновкиДанных("Период");
	ЗначПарам = НастройкиКДМастерОтчета.ПараметрыДанных.НайтиЗначениеПараметра(Период);
	Период_Значение = ЗначПарам.Значение;
	ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.ПараметрыДанных.УстановитьЗначениеПараметра(Период, Период_Значение);
	
	Если 	  ЭтаФорма.Параметры.ИмяПоказателяКРасшифровке = "Количество задач всего" Тогда
		// доп. обработка не требуется
	ИначеЕсли ЭтаФорма.Параметры.ИмяПоказателяКРасшифровке = "Количество успешных переключений" Тогда
		ЭлОтбора = ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.Отбор.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));	
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ЗвонокЗакрытияСигнатура");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.НачинаетсяС;
		ЭлОтбора.ПравоеЗначение = "0#" ;
		ЭлОтбора.Использование 	=  Истина;
	ИначеЕсли ЭтаФорма.Параметры.ИмяПоказателяКРасшифровке = "Количество закрытых вручную" Тогда
		ЭлОтбора = ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.Отбор.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));	
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ЗвонокЗакрытияСигнатура");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.НеСодержит;
		ЭлОтбора.ПравоеЗначение = "#" ;
		ЭлОтбора.Использование 	=  Истина;	
	ИначеЕсли ЭтаФорма.Параметры.ИмяПоказателяКРасшифровке = "Доля успешных закрытий" Тогда
		ГрОтбора = ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.Отбор.Элементы.Добавить(Тип("ГруппаЭлементовОтбораКомпоновкиДанных"));
		ГрОтбора.ТипГруппы = ТипГруппыЭлементовОтбораКомпоновкиДанных.ГруппаИли;
		
		ЭлОтбора = ГрОтбора.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));	
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ЗвонокЗакрытияСигнатура");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.НачинаетсяС;
		ЭлОтбора.ПравоеЗначение = "0#" ;
		ЭлОтбора.Использование 	=  Истина;
		
		ЭлОтбора = ГрОтбора.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));	
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ЗвонокЗакрытияСигнатура");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.НеСодержит;
		ЭлОтбора.ПравоеЗначение = "#" ;
		ЭлОтбора.Использование 	=  Истина;
	ИначеЕсли ЭтаФорма.Параметры.ИмяПоказателяКРасшифровке = "Количество успешных переключений не обработанных в срок" Тогда
		
		НормаВМинутах = Новый ПараметрКомпоновкиДанных("НормаВМинутах");
		ЗначПарам = НастройкиКДМастерОтчета.ПараметрыДанных.НайтиЗначениеПараметра(НормаВМинутах);
		НормаВМинутах_Значение = ЗначПарам.Значение;

		ЭлОтбора = ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.Отбор.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ДлительностьОбработкиМин");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.Больше;
		ЭлОтбора.ПравоеЗначение = НормаВМинутах_Значение;
		ЭлОтбора.Использование 	=  Истина;	
		
	//28.11.2016
	ИначеЕсли  ЭтаФорма.Параметры.ИмяПоказателяКРасшифровке = "Количество закрытых вручную по причине СПАМ" Тогда
		
		ЭлОтбора = ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.Отбор.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));	
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ЗвонокЗакрытияСигнатура");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.НеСодержит;
		ЭлОтбора.ПравоеЗначение = "#" ;
		ЭлОтбора.Использование 	=  Истина;	
	
		ЭлОтбора = ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.Отбор.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));	
		ЭлОтбора.ЛевоеЗначение = Новый ПолеКомпоновкиДанных("ПричинаРучногоЗакрытия");
		ЭлОтбора.ВидСравнения=ВидСравненияКомпоновкиДанных.Содержит;
		ЭлОтбора.ПравоеЗначение = ЭтаФорма.Параметры.ОтборПричинаРучногоЗакрытияСПАМ ;
		ЭлОтбора.Использование 	=  Истина;
	
	КонецЕсли;
	
	
	
	//Сформируй отчет
	ОтчОбъект = РеквизитФормыВЗначение("Отчет");
	ОтчОбъект.СкомпоноватьРезультат(ЭтаФорма.Результат);
	
КонецПроцедуры

