﻿Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
	СКД = ПолучитьМакет("СтруктураПереведенныхЗвонковЕКЦ");	
	СтруктураПереведенныхЗвонковЕКЦ(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка, СКД);	 

КонецПроцедуры

Процедура СтруктураПереведенныхЗвонковЕКЦ(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка, СКД)
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	Звонки.АбонентВнешний КАК Телефон,
	|	Звонки.Сигнатура КАК Сигнатура,
	|	ЕСТЬNULL(ЗвонкиСтатОбщая.КЦОжидание, 0) КАК КЦОжидание,
	|	ЕСТЬNULL(ЗвонкиСтатОбщая.КЦРазговор, 0) КАК КЦРазговор,
	|	ЕСТЬNULL(ЗвонкиСтатОбщая.ОПОжидание, 0) КАК ОПОжидание,
	|	ЕСТЬNULL(ЗвонкиСтатОбщая.ОПРазговор, 0) КАК ОПРазговор,
	|	ЕСТЬNULL(ЗвонкиДоп.ЦелеваяТочка, ЗНАЧЕНИЕ(Справочник.ТочкиЦелевые.ПустаяСсылка)) КАК ЦелеваяТочка,
	|	ЕСТЬNULL(ЗвонкиДоп.ЦелеваяТочка.Наименование, """") КАК ЦелеваяТочкаНаименование
	|ПОМЕСТИТЬ ВТ01_База
	|ИЗ
	|	РегистрСведений.Звонки КАК Звонки
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиСтатОбщая КАК ЗвонкиСтатОбщая
	|		ПО Звонки.Сигнатура = ЗвонкиСтатОбщая.Сигнатура
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиДоп КАК ЗвонкиДоп
	|		ПО Звонки.Сигнатура = ЗвонкиДоп.Сигнатура
	|ГДЕ
	|	Звонки.Дата МЕЖДУ &Начало И &Окончание
	|	И ЗвонкиСтатОбщая.КЦСсылка = &КЦСсылка
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ01.Телефон КАК Телефон,
	|	ВТ01.Сигнатура КАК Сигнатура,
	|	ВТ01.КЦОжидание КАК КЦОжидание,
	|	ВТ01.КЦРазговор КАК КЦРазговор,
	|	ВТ01.ОПОжидание КАК ОПОжидание,
	|	ВТ01.ОПРазговор КАК ОПРазговор,
	|	ВТ01.ЦелеваяТочка КАК ЦелеваяТочка,
	|	ВТ01.ЦелеваяТочкаНаименование КАК ЦелеваяТочкаНаименование,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПОжидание + ВТ01.ОПРазговор = 0
	|			ТОГДА ВЫБОР
	|					КОГДА ВТ01.КЦРазговор <= 5
	|						ТОГДА ""Непринят ЕКЦ""
	|					ИНАЧЕ ""Остался на операторе""
	|				КОНЕЦ
	|		ИНАЧЕ ""Звонок переведен""
	|	КОНЕЦ КАК СтатусЗвонка
	|ПОМЕСТИТЬ ВТ03_ПереведенныеЗвонки
	|ИЗ
	|	ВТ01_База КАК ВТ01
	|ГДЕ
	|	ВЫБОР
	|			КОГДА ВТ01.ОПОжидание + ВТ01.ОПРазговор = 0
	|				ТОГДА ВЫБОР
	|						КОГДА ВТ01.КЦРазговор <= 5
	|							ТОГДА ""Непринят ЕКЦ""
	|						ИНАЧЕ ""Остался на операторе""
	|					КОНЕЦ
	|			ИНАЧЕ ""Звонок переведен""
	|		КОНЕЦ = ""Звонок переведен""
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ03.Телефон КАК Телефон,
	|	ВТ03.Сигнатура КАК Сигнатура,
	|	ВТ03.ЦелеваяТочка КАК ЦелеваяТочка,
	|	ВЫБОР
	|		КОГДА ВТ03.ОПРазговор = 0
	|			ТОГДА ВЫБОР
	|					КОГДА ВТ03.ЦелеваяТочка = ЗНАЧЕНИЕ(Справочник.ТочкиЦелевые.ПустаяСсылка)
	|						ТОГДА ""Непринят ОП нецелевой звонок""
	|					ИНАЧЕ ""Непринят ОП целевой звонок""
	|				КОНЕЦ
	|		ИНАЧЕ ВЫБОР
	|				КОГДА ВТ03.ЦелеваяТочка = ЗНАЧЕНИЕ(Справочник.ТочкиЦелевые.ПустаяСсылка)
	|					ТОГДА ""Принят нецелевой звонок""
	|				ИНАЧЕ ""Принят ОП целевой звонок""
	|			КОНЕЦ
	|	КОНЕЦ КАК Статус,
	|	ВЫБОР
	|		КОГДА ВТ03.ЦелеваяТочкаНаименование ПОДОБНО ""СТО %""
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ЕстьСТО
	|ПОМЕСТИТЬ ВТ04
	|ИЗ
	|	ВТ03_ПереведенныеЗвонки КАК ВТ03
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Анкета.Ответ КАК Ответ,
	|	Анкета.Телефон КАК Телефон,
	|	Анкета.Сигнатура КАК Сигнатура,
	|	МАКСИМУМ(Анкета.Период) КАК Период
	|ПОМЕСТИТЬ ВТ05_Ответ_ТипОбращенияСТО
	|ИЗ
	|	РегистрСведений.АнкетыРасширенные.СрезПоследних(
	|			,
	|			(Телефон, Сигнатура) В
	|					(ВЫБРАТЬ
	|						ВТ03.Телефон,
	|						ВТ03.Сигнатура
	|					ИЗ
	|						ВТ03_ПереведенныеЗвонки КАК ВТ03)
	|				И Вопрос = &Вопрос_ТипОбращенияСТО) КАК Анкета
	|
	|СГРУППИРОВАТЬ ПО
	|	Анкета.Ответ,
	|	Анкета.Телефон,
	|	Анкета.Сигнатура
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ04.Телефон КАК Телефон,
	|	ВТ04.Сигнатура КАК Сигнатура,
	|	ВТ04.ЦелеваяТочка КАК ЦелеваяТочка,
	|	ВТ04.Статус КАК Статус,
	|	ВТ04.ЕстьСТО КАК ЕстьСТО,
	|	ЕСТЬNULL(ВТ05.Ответ.Наименование, ""<не заполнено>"") КАК Ответ,
	|	ВЫБОР
	|		КОГДА ВТ05.Ответ.Наименование ЕСТЬ NULL
	|			ТОГДА 0
	|		ИНАЧЕ 1
	|	КОНЕЦ КАК ЕстьОтвет
	|ПОМЕСТИТЬ ВТ06
	|ИЗ
	|	ВТ04 КАК ВТ04
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ05_Ответ_ТипОбращенияСТО КАК ВТ05
	|		ПО ВТ04.Телефон = ВТ05.Телефон
	|			И ВТ04.Сигнатура = ВТ05.Сигнатура
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ06.Телефон КАК Телефон,
	|	ВТ06.Сигнатура КАК Сигнатура,
	|	ВТ06.ЦелеваяТочка КАК ЦелеваяТочка,
	|	ВТ06.Статус КАК Статус,
	|	ВТ06.Ответ КАК Ответ,
	|	1 КАК Количество
	|ИЗ
	|	ВТ06 КАК ВТ06
	|ГДЕ
	|	ВЫБОР
	|			КОГДА ВТ06.ЕстьОтвет + ВТ06.ЕстьСТО >= 1
	|				ТОГДА ИСТИНА
	|			ИНАЧЕ ЛОЖЬ
	|		КОНЕЦ";
	
	Запрос.УстановитьПараметр("Начало", 	Период.ДатаНачала);
	Запрос.УстановитьПараметр("Окончание",  Период.ДатаОкончания);
	Запрос.УстановитьПараметр("КЦСсылка",	Справочники.Предприятие.НайтиПоКоду("000000265"));	
	Запрос.УстановитьПараметр("Вопрос_ТипОбращенияСТО", Справочники.ИдентификаторыСтрок.НайтиПоНаименованию("Тип обращения СТО"));
	
	РезультатЗапроса = Запрос.Выполнить();
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат;
	КонецЕсли;

	ТЗ = РезультатЗапроса.Выгрузить();
		
	ВнешниеНаборыДанных = Новый Структура();
	ВнешниеНаборыДанных.Вставить("ТЗ", ТЗ);
	
	Настройки = СКД.НастройкиПоУмолчанию;
	
	КомпоновщикМакета 			= Новый КомпоновщикМакетаКомпоновкиДанных();
	МакетКомпоновки 			= КомпоновщикМакета.Выполнить(СКД, Настройки, ДанныеРасшифровки);
	ПроцессорКомпоновкиДанных 	= Новый ПроцессорКомпоновкиДанных();
	ПроцессорКомпоновкиДанных.Инициализировать(МакетКомпоновки, ВнешниеНаборыДанных, ДанныеРасшифровки);
	 
	ПроцессорВывода = Новый ПроцессорВыводаРезультатаКомпоновкиДанныхВТабличныйДокумент();
	ПроцессорВывода.УстановитьДокумент(ДокументРезультат);
	ПроцессорВывода.Вывести(ПроцессорКомпоновкиДанных);	
	
	ДокументРезультат.ПоказатьУровеньГруппировокСтрок(1);
	 
КонецПроцедуры


