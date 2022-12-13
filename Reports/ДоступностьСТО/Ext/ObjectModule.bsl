﻿Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	
	СтандартнаяОбработка = Ложь;
	
	ПараметрыДанных = КомпоновщикНастроек.Настройки.ПараметрыДанных;
	ПараметрыДанных.УстановитьЗначениеПараметра("Начало", 		Период.ДатаНачала);
	ПараметрыДанных.УстановитьЗначениеПараметра("Окончание", 	Период.ДатаОкончания);
	
	//Получи таблицу агентов целевых очередей
	//-------------------------------------------------------
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	ТочкиЦелевые.Очередь.Наименование КАК ОчередьНаименование
	|ИЗ
	|	Справочник.ТочкиЦелевые КАК ТочкиЦелевые
	|ГДЕ
	|	ТочкиЦелевые.Ссылка В ИЕРАРХИИ
	|			(ВЫБРАТЬ
	|				ТЦ.Ссылка
	|			ИЗ
	|				Справочник.ТочкиЦелевые КАК ТЦ
	|			ГДЕ
	|				ТЦ.Код = ""000000014"")
	|	И НЕ ТочкиЦелевые.Очередь.Код = """"
	|	И ТочкиЦелевые.ЭтоГруппа = ЛОЖЬ";
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Сообщ = Новый СообщениеПользователю();
		Сообщ.Текст = "Ошибка получения целевых очередей СТО";
		Сообщ.Сообщить();
		Отказ = Истина;
		Возврат;
	КонецЕсли;
	ИменаЦелевыхОчередей = РезультатЗапроса.Выгрузить().ВыгрузитьКолонку(0);
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	ВЫРАЗИТЬ(Агенты.membername КАК СТРОКА(4)) КАК Агент,
	|	Агенты.queue_name КАК ИмяОчереди
	|ИЗ
	|	ВнешнийИсточникДанных.AsteriskNnov.Таблица.Агенты КАК Агенты
	|ГДЕ
	|	Агенты.queue_name В(&ИменаЦелевыхОчередей)";
	Запрос.УстановитьПараметр("ИменаЦелевыхОчередей", ИменаЦелевыхОчередей);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	Если РезультатЗапроса.Пустой() Тогда
		Сообщ = Новый СообщениеПользователю();
		Сообщ.Текст = "Ошибка получения агентов целевых очередей СТО";
		Сообщ.Сообщить();
		Отказ = Истина;
		Возврат;
	КонецЕсли;
	АгентыОчередей = РезультатЗапроса.Выгрузить();
	
	//Сформируй главный запрос отчета
	//---------------------------------
	Запрос = Новый Запрос();
	Если ВыбранныйВариантОтчета = "а" Тогда
		Запрос.Текст = ПоказателиВИзмерении();
	ИначеЕсли ВыбранныйВариантОтчета = "б" Тогда
		Запрос.Текст = ПоказателиВРесурсахДетально();
	КонецЕсли;
		
	Запрос.УстановитьПараметр("Начало", 	Период.ДатаНачала);
	Запрос.УстановитьПараметр("Окончание",	Период.ДатаОкончания);
	Запрос.УстановитьПараметр("Т",			АгентыОчередей);
	
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	ТЗ = РезультатЗапроса.Выгрузить();
	
	ВнешниеНаборыДанных = Новый Структура();
	ВнешниеНаборыДанных.Вставить("ТЗ", ТЗ);
	
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

	
Функция ПоказателиВРесурсахДетально()
	
	ПоказателиВРесурсахДетально = 
	"ВЫБРАТЬ
	|	ТочкиЦелевые.Очередь.Код КАК ОчередьКод,
	|	ТочкиЦелевые.Очередь.Наименование КАК ОчередьНаименование,
	|	ТочкиЦелевые.Очередь КАК Очередь,
	|	ТочкиЦелевые.Ссылка КАК ТочкаЦелевая,
	|	ТочкиЦелевые.Ссылка.Родитель КАК ТочкаЦелеваяРодитель
	|ПОМЕСТИТЬ ВТ00_Очереди
	|ИЗ
	|	Справочник.ТочкиЦелевые КАК ТочкиЦелевые
	|ГДЕ
	|	ТочкиЦелевые.Ссылка В ИЕРАРХИИ
	|			(ВЫБРАТЬ
	|				ТЦ.Ссылка
	|			ИЗ
	|				Справочник.ТочкиЦелевые КАК ТЦ
	|			ГДЕ
	|				ТЦ.Код = ""000000014"")
	|	И НЕ ТочкиЦелевые.Очередь.Код = """"
	|	И ТочкиЦелевые.ЭтоГруппа = ЛОЖЬ
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Звонки.Сигнатура КАК Сигнатура,
	|	Звонки.АбонентВнешний КАК АбонентВнешний,
	|	Звонки.Дата КАК Дата,
	|	Звонки.АбонентВнутренний.Код КАК АбонентВнутренний,
	|	Звонки.Принят КАК Принят,
	|	ЕСТЬNULL(Стат.ОПОжидание, 0) КАК ОПОжидание,
	|	ЕСТЬNULL(Стат.ОПРазговор, 0) КАК ОПРазговор,
	|	Маршруты.Оператор КАК Оператор,
	|	ВТ00.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ00.ТочкаЦелеваяРодитель КАК ТочкаЦелеваяРодитель,
	|	ВТ00.Очередь КАК Очередь
	|ПОМЕСТИТЬ ВТ01_ВсеПоступившиеВОчередьЗвонки
	|ИЗ
	|	РегистрСведений.Звонки КАК Звонки
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиСтатОбщая КАК Стат
	|		ПО Звонки.Сигнатура = Стат.Сигнатура
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиМаршруты КАК Маршруты
	|		ПО Звонки.Сигнатура = Маршруты.Сигнатура
	|			И (Маршруты.КодСобытия = ""ENTERQUEUE"")
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ00_Очереди КАК ВТ00
	|		ПО (Маршруты.Оператор = ВТ00.Очередь)
	|ГДЕ
	|	Звонки.Дата МЕЖДУ &Начало И &Окончание
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Т.Агент КАК Агент,
	|	Т.ИмяОчереди КАК ИмяОчереди
	|ПОМЕСТИТЬ ВТ02_АгентыОчередей
	|ИЗ
	|	&Т КАК Т
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	ВТ01.Сигнатура КАК Сигнатура,
	|	ВТ01.АбонентВнешний КАК АбонентВнешний,
	|	НАЧАЛОПЕРИОДА(ВТ01.Дата, ДЕНЬ) КАК Дата,
	|	ВТ01.Дата КАК ДатаВремя,
	|	ВТ01.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ01.ТочкаЦелеваяРодитель КАК ТочкаЦелеваяРодитель,
	|	ВТ01.Очередь КАК Очередь,
	|	ВТ01.ОПОжидание КАК ОПОжидание,
	|	ВТ01.ОПРазговор КАК ОПРазговор,
	|	1 КАК Всего,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПРазговор > 5
	|				И ВТ01.Принят = ИСТИНА
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК Принят,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПРазговор <= 5
	|				ИЛИ ВТ01.Принят = ЛОЖЬ
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК НеПринят,
	|	ВЫБОР
	|		КОГДА НЕ ВТ02.Агент ЕСТЬ NULL
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ЗавершилсяНаОператореСервисБюро,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПОжидание <= 5
	|				И Маршруты1.КодСобытия = ""ABANDON""
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ПропущенСвременемОжиданияНеболее5иСбросилАбонент
	|ИЗ
	|	ВТ01_ВсеПоступившиеВОчередьЗвонки КАК ВТ01
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ02_АгентыОчередей КАК ВТ02
	|		ПО ВТ01.АбонентВнутренний = ВТ02.Агент
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиМаршруты КАК Маршруты1
	|		ПО ВТ01.Сигнатура = Маршруты1.Сигнатура
	|			И (ВТ01.ОПРазговор = 0)
	|			И (Маршруты1.КодСобытия = ""ABANDON"")";
	
	Возврат ПоказателиВРесурсахДетально;

КонецФункции


Функция ПоказателиВИзмерении()
	
	ПоказателиВИзмерении = 
	"ВЫБРАТЬ
	|	ТочкиЦелевые.Очередь.Код КАК ОчередьКод,
	|	ТочкиЦелевые.Очередь.Наименование КАК ОчередьНаименование,
	|	ТочкиЦелевые.Очередь КАК Очередь,
	|	ТочкиЦелевые.Ссылка КАК ТочкаЦелевая,
	|	ТочкиЦелевые.Ссылка.Родитель КАК ТочкаЦелеваяРодитель
	|ПОМЕСТИТЬ ВТ00_Очереди
	|ИЗ
	|	Справочник.ТочкиЦелевые КАК ТочкиЦелевые
	|ГДЕ
	|	ТочкиЦелевые.Ссылка В ИЕРАРХИИ
	|			(ВЫБРАТЬ
	|				ТЦ.Ссылка
	|			ИЗ
	|				Справочник.ТочкиЦелевые КАК ТЦ
	|			ГДЕ
	|				ТЦ.Код = ""000000014"")
	|	И НЕ ТочкиЦелевые.Очередь.Код = """"
	|	И ТочкиЦелевые.ЭтоГруппа = ЛОЖЬ
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Звонки.Сигнатура КАК Сигнатура,
	|	Звонки.Дата КАК Дата,
	|	Звонки.АбонентВнутренний.Код КАК АбонентВнутренний,
	|	Звонки.Принят КАК Принят,
	|	ЕСТЬNULL(Стат.ОПОжидание, 0) КАК ОПОжидание,
	|	ЕСТЬNULL(Стат.ОПРазговор, 0) КАК ОПРазговор,
	|	Маршруты.Оператор КАК Оператор,
	|	ВТ00.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ00.ТочкаЦелеваяРодитель КАК ТочкаЦелеваяРодитель,
	|	ВТ00.Очередь КАК Очередь
	|ПОМЕСТИТЬ ВТ01_ВсеПоступившиеВОчередьЗвонки
	|ИЗ
	|	РегистрСведений.Звонки КАК Звонки
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиСтатОбщая КАК Стат
	|		ПО Звонки.Сигнатура = Стат.Сигнатура
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиМаршруты КАК Маршруты
	|		ПО Звонки.Сигнатура = Маршруты.Сигнатура
	|			И (Маршруты.КодСобытия = ""ENTERQUEUE"")
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ00_Очереди КАК ВТ00
	|		ПО (Маршруты.Оператор = ВТ00.Очередь)
	|ГДЕ
	|	Звонки.Дата МЕЖДУ &Начало И &Окончание
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Т.Агент КАК Агент,
	|	Т.ИмяОчереди КАК ИмяОчереди
	|ПОМЕСТИТЬ ВТ02_АгентыОчередей
	|ИЗ
	|	&Т КАК Т
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ РАЗЛИЧНЫЕ
	|	ВТ01.Сигнатура КАК Сигнатура,
	|	НАЧАЛОПЕРИОДА(ВТ01.Дата, ДЕНЬ) КАК Дата,
	|	ВТ01.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ01.ТочкаЦелеваяРодитель КАК ТочкаЦелеваяРодитель,
	|	1 КАК Всего,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПРазговор > 5
	|				И ВТ01.Принят = ИСТИНА
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК Принят,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПРазговор <= 5
	|				ИЛИ ВТ01.Принят = ЛОЖЬ
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК НеПринят,
	|	ВЫБОР
	|		КОГДА НЕ ВТ02.Агент ЕСТЬ NULL
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ЗавершилсяНаОператореСервисБюро,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПРазговор <= 5
	|			ТОГДА ВЫБОР
	|					КОГДА НЕ ВТ02.Агент ЕСТЬ NULL
	|						ТОГДА 1
	|					ИНАЧЕ 0
	|				КОНЕЦ
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ЗавершилсяНаОператореСервисБюроНеПринят,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПРазговор <= 5
	|			ТОГДА ВЫБОР
	|					КОГДА НЕ ВТ02.Агент ЕСТЬ NULL
	|						ТОГДА 0
	|					ИНАЧЕ 1
	|				КОНЕЦ
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ЗавершилсяНеНаОператореСервисБюроНеПринят,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПОжидание * ВЫБОР
	|				КОГДА НЕ ВТ02.Агент ЕСТЬ NULL
	|					ТОГДА 1
	|				ИНАЧЕ 0
	|			КОНЕЦ > 20
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ЗавершилсяНаСервисБюроИВремяОжиданияБолееНормы,
	|	ВЫБОР
	|		КОГДА ВТ01.ОПОжидание <= 5
	|				И Маршруты1.КодСобытия = ""ABANDON""
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ПропущенСвременемОжиданияНеболее5иСбросилАбонент
	|ПОМЕСТИТЬ ВТ021
	|ИЗ
	|	ВТ01_ВсеПоступившиеВОчередьЗвонки КАК ВТ01
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ02_АгентыОчередей КАК ВТ02
	|		ПО ВТ01.АбонентВнутренний = ВТ02.Агент
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиМаршруты КАК Маршруты1
	|		ПО ВТ01.Сигнатура = Маршруты1.Сигнатура
	|			И (ВТ01.ОПРазговор = 0)
	|			И (Маршруты1.КодСобытия = ""ABANDON"")
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	вт021.Дата КАК Дата,
	|	вт021.ТочкаЦелевая КАК ТочкаЦелевая,
	|	вт021.ТочкаЦелеваяРодитель КАК ТочкаЦелеваяРодитель,
	|	СУММА(вт021.Всего) КАК Всего,
	|	СУММА(вт021.Принят) КАК Принят,
	|	СУММА(вт021.НеПринят) КАК НеПринят,
	|	СУММА(вт021.ЗавершилсяНаОператореСервисБюро) КАК ЗавершилсяНаОператореСервисБюро,
	|	СУММА(вт021.ЗавершилсяНаОператореСервисБюроНеПринят) КАК ЗавершилсяНаОператореСервисБюроНеПринят,
	|	СУММА(вт021.ЗавершилсяНеНаОператореСервисБюроНеПринят) КАК ЗавершилсяНеНаОператореСервисБюроНеПринят,
	|	СУММА(вт021.ЗавершилсяНаСервисБюроИВремяОжиданияБолееНормы) КАК ЗавершилсяНаСервисБюроИВремяОжиданияБолееНормы,
	|	СУММА(вт021.ПропущенСвременемОжиданияНеболее5иСбросилАбонент) КАК ПропущенСвременемОжиданияНеболее5иСбросилАбонент,
	|	ВЫБОР
	|		КОГДА СУММА(вт021.Всего) <> 0
	|			ТОГДА ВЫРАЗИТЬ(СУММА(вт021.НеПринят) / СУММА(вт021.Всего) * 100 КАК ЧИСЛО(10, 2))
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК ДоляПропущенных
	|ПОМЕСТИТЬ ВТ03
	|ИЗ
	|	ВТ021 КАК вт021
	|
	|СГРУППИРОВАТЬ ПО
	|	вт021.Дата,
	|	вт021.ТочкаЦелевая,
	|	вт021.ТочкаЦелеваяРодитель
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	""Всего"" КАК ИдПараметра,
	|	""Поступило"" КАК ИмяПараметра,
	|	11 КАК ПорядокПараметра,
	|	ВТ03.Всего КАК ЗначениеПараметра,
	|	1 КАК ЗначениеПараметра1,
	|	0 КАК СчитатьОтошениеПараметров,
	|	""Общий итог"" КАК ГруппировкаОбщегоИтога,
	|	ВТ03.ТочкаЦелеваяРодитель КАК ТочкаЦелеваяРодитель,
	|	ВТ03.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ03.Дата КАК Дата
	|ИЗ
	|	ВТ03 КАК ВТ03
	|
	|ОБЪЕДИНИТЬ ВСЕ
	|
	|ВЫБРАТЬ
	|	""Принят"",
	|	""Принят"",
	|	12,
	|	ВТ03.Принят,
	|	1,
	|	0,
	|	""Общий итог"",
	|	ВТ03.ТочкаЦелеваяРодитель,
	|	ВТ03.ТочкаЦелевая,
	|	ВТ03.Дата
	|ИЗ
	|	ВТ03 КАК ВТ03
	|
	|ОБЪЕДИНИТЬ ВСЕ
	|
	|ВЫБРАТЬ
	|	""Пропущено"",
	|	""Пропущено"",
	|	13,
	|	ВТ03.НеПринят,
	|	1,
	|	0,
	|	""Общий итог"",
	|	ВТ03.ТочкаЦелеваяРодитель,
	|	ВТ03.ТочкаЦелевая,
	|	ВТ03.Дата
	|ИЗ
	|	ВТ03 КАК ВТ03
	|
	|ОБЪЕДИНИТЬ ВСЕ
	|
	|ВЫБРАТЬ
	|	""НепринятКромеОжидание5БросилАбонент"",
	|	""Пропущено без учета сбросов"",
	|	14,
	|	ВТ03.НеПринят - ВТ03.ПропущенСвременемОжиданияНеболее5иСбросилАбонент,
	|	1,
	|	0,
	|	""Общий итог"",
	|	ВТ03.ТочкаЦелеваяРодитель,
	|	ВТ03.ТочкаЦелевая,
	|	ВТ03.Дата
	|ИЗ
	|	ВТ03 КАК ВТ03
	|
	|ОБЪЕДИНИТЬ ВСЕ
	|
	|ВЫБРАТЬ
	|	""_ВычДоля"",
	|	""Доля пропущенных, %"",
	|	15,
	|	ВТ03.НеПринят - ВТ03.ПропущенСвременемОжиданияНеболее5иСбросилАбонент,
	|	ВТ03.Всего * 0.01,
	|	1,
	|	""Общий итог"",
	|	ВТ03.ТочкаЦелеваяРодитель,
	|	ВТ03.ТочкаЦелевая,
	|	ВТ03.Дата
	|ИЗ
	|	ВТ03 КАК ВТ03";
	
	Возврат ПоказателиВИзмерении;

КонецФункции 

