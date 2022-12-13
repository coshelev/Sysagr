﻿
Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;

	РезультатЗапроса = РезультатЗапроса();	
			
	ВнешниеНаборыДанных = Новый Структура();
	ВнешниеНаборыДанных.Вставить("ТЗ", РезультатЗапроса);
	
	СКД = ПолучитьМакет("ОсновнаяСКД");
	
	Настройки = ЭтотОбъект.КомпоновщикНастроек.Настройки;
	
	КомпоновщикМакета = Новый КомпоновщикМакетаКомпоновкиДанных();
	МакетКомпоновки = КомпоновщикМакета.Выполнить(СКД, Настройки, ДанныеРасшифровки);
	ПроцессорКомпоновкиДанных = Новый ПроцессорКомпоновкиДанных();
	ПроцессорКомпоновкиДанных.Инициализировать(МакетКомпоновки, ВнешниеНаборыДанных, ДанныеРасшифровки);
	 
	ПроцессорВывода = Новый ПроцессорВыводаРезультатаКомпоновкиДанныхВТабличныйДокумент();
	ПроцессорВывода.УстановитьДокумент(ДокументРезультат);
	ПроцессорВывода.Вывести(ПроцессорКомпоновкиДанных);
	
	ДокументРезультат.ПоказатьУровеньГруппировокСтрок(1);
КонецПроцедуры

Функция РезультатЗапроса() Экспорт
	//Выполни запрос в базе ОУ по выставкам и встречам
	//-------------------------------------------------
	ДатаНачала					=	Период.ДатаНачала; 
	ДатаОкончания				=	Период.ДатаОкончания;
	
	// Заполнит ТЧ Звонки, Встречи, Задачи по эл. почте
	//-----------------------------------------------------
	СформироватьБазовыеТаблицыЗвонкиВстречиЗадачиЭлПочты(ДатаНачала, ДатаОкончания, "");
	
	ЗначениеПоУмолчанию = Ложь;
	
	//Получи иерархию каналов и сайтов звонков из учетной политики в таблицу значений
	ИмяИерархии = "Отчет_ВходящиеЗвонкиПоКлассифайдам_Иерархия3";
	ИерархияМаркетинга = ОбработкаОтчетов.ПолучитьИерархиюПоИмени(ИмяИерархии);
	Если ИерархияМаркетинга.Количество()=0 Тогда
		Сообщить(СтрШаблон("Не найдена иерархия %1",ИерархияМаркетинга));
	КонецЕсли;

	 //Статусы звонков в ОУ с 07.05.2020
	 //--------------------------------
	 //Первое слово ОТКАЗ/ВРАБОТЕ означет что произошло со звонком (отказ от обратботки или создание/привязка к сделке)
	 
	//ЗВОНОК-АВТОПРИВЯЗКА   , пропущенный звонок закрывается следующим состоявшимся звонком
	//ОТКАЗ-ВРАБОТЕ			, означает в работе у другого менеджера
	//ОТКАЗ-КЛИЕНТ			, означает клиент отказался от покупки
	//ОТКАЗ-НЕЦЕЛЕВОЙ       , означает, что звонок не связан с покупкой/продажей автомобиля
	//ОТКАЗ-ОПЕРАТОР		, означает, что менеджер откзывается от обработки этого звонка, не будет перезванивать. Устанавливается состояние "Справочник.СтатусыОбъектов.ОбщийОтменен" 
	//РАБОТА-АВТОПРИВЯЗКА   , звонок автоматически привязался к существующей сделке
	//РАБОТА-НОВЫЙ			, значит по звонку создана новая сделка
	//РАБОТА-ПРИВЯЗКА       , значит менеджер сам привязал звонок к существущей сделке
	//<пустая строка>		, значит в состоянии Новый ("ожидает обработки")
	
	//ВТ00_ЦелевыеАгрегатора - звонки признанные целевыми в Агрегаторе и прошедшие через контакт-центр
	//ВТ01_ЦелевыеОУ	- звонки целевые ОУ
	
	//	КоличествоА - признанный целевым в Агрегаторе, прошедный через контакт-центр, но отсутствующий в целевых ОУ
	//	КоличествоБ - признанный целевым в ОУ, но не целевой в Агрегаторе
    //	КоличествоГ - целевой в Агр, нет в ОУ, но это не ошибка, сотрудник определился, но он не принял звонок. Т.е. это непринятый
	//	Количество1 - есть в ОУ, непринят, по нему возможно есть собственный исходящий, но он не входит в период отчета
	//	Количество2 - ЦЕЛЕВОЙ ОУ, ожидает обработки, состояние = новый, статус = <пустая строка>
	//	Количество3 - целевой в ОУ, клиент отказался от покупки, статус = ОТКАЗ-КЛИЕНТ
	//	Количество4 - нецелевой в ОУ, статус = "ОТКАЗ-НЕЦЕЛЕВОЙ"
	//	Количество5 - ЦЕЛЕВОЙ ОУ, статус = "ЗВОНОК-АВТОПРИВЯЗКА", в основании этого звонка - звонок ,которым перезвонили 
	//	Количество6 - нецелевой,статус= "ОТКАЗ-ОПЕРАТОР"
	//	Количество7 - целевой ОУ, повторный
	//	Количество8 - ЦЕЛЕВОЙ ОУ, создана сделка
	//	Количество81,
	//	КоличествоИтогоПоСтатусам - сумма количеств по разным статусам ОУ
	//	КоличествоОбщееБезПочты - общее количество звонков из ОУ, без учета статуса, т.е. с учетом ошибочных
	//	КоличествоЦелевыхБезПочты
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	Звонки.Сигнатура КАК Сигнатура,
	|	Звонки.Дата КАК ДатаЗвонка,
	|	Звонки.ЭтоВходящий КАК Входящий,
	|	Звонки.Принят КАК Принят,
	|	ЗвонкиДоп.ЦелеваяТочка КАК ЦелеваяТочка,
	|	ЗвонкиДоп.СотрудникОУ КАК Сотрудник,
	|	0 КАК КоличествоА,
	|	0 КАК КоличествоБ,
	|	0 КАК Количество1,
	|	0 КАК Количество2,
	|	0 КАК Количество3,
	|	0 КАК Количество4,
	|	0 КАК Количество5,
	|	0 КАК Количество6,
	|	0 КАК Количество7,
	|	0 КАК Количество8,
	|	0 КАК Количество9,
	|	0 КАК КоличествоИтогоПоСтатусам,
	|	0 КАК КоличествоОбщееБезПочты,
	|	0 КАК КоличествоОбщее,
	|	0 КАК КоличествоЦелевыхБезПочты,
	|	0 КАК КоличествоЦелевых,
	|	0 КАК ОбщийЦелевой,
	|	""<Нет направления>"" КАК Направление
	|ПОМЕСТИТЬ ВТ00_ЦелевыеАгрегатора
	|ИЗ
	|	РегистрСведений.Звонки КАК Звонки
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиДоп КАК ЗвонкиДоп
	|		ПО Звонки.Сигнатура = ЗвонкиДоп.Сигнатура
	|ГДЕ
	|	Звонки.Дата МЕЖДУ &ДатаНачала И &ДатаОкончания
	|	И ВЫБОР
	|			КОГДА Звонки.ЭтоВходящий
	|				ТОГДА ИСТИНА
	|			ИНАЧЕ ВЫБОР
	|					КОГДА Звонки.Инициатор В (&ТелефоныКонтактЦентра)
	|						ТОГДА ИСТИНА
	|					ИНАЧЕ ЛОЖЬ
	|				КОНЕЦ
	|		КОНЕЦ
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Т.ДатаЗвонка КАК ДатаЗвонка,
	|	Т.Сигнатура КАК Сигнатура,
	|	Т.СотрудникОУГУИД КАК СотрудникОУГУИД,
	|	Т.Входящий КАК Входящий,
	|	Т.Количество1 КАК Количество1,
	|	Т.Количество2 КАК Количество2,
	|	Т.Количество3 КАК Количество3,
	|	Т.Количество4 КАК Количество4,
	|	Т.Количество5 КАК Количество5,
	|	Т.Количество6 КАК Количество6,
	|	Т.Количество7 КАК Количество7,
	|	Т.Количество8 КАК Количество8,
	|	0 КАК Количество9,
	|	Т.КоличествоИтогоПоСтатусам КАК КоличествоИтогоПоСтатусам,
	|	Т.КоличествоОбщееБезПочты КАК КоличествоОбщееБезПочты,
	|	Т.КоличествоОбщееБезПочты КАК КоличествоОбщее,
	|	0 КАК КоличествоЦелевыхБезПочты,
	|	0 КАК КоличествоЦелевых,
	|	0 КАК ОбщийЦелевой,
	|	1 КАК Принят,
	|	Т.Направление КАК Направление
	|ПОМЕСТИТЬ ВТ01_ЦелевыеОУ
	|ИЗ
	|	&РеестрЦелевыхТек КАК Т
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ01.ДатаЗвонка КАК ДатаЗвонка,
	|	ВТ01.Сигнатура КАК Сигнатура,
	|	ВТ01.СотрудникОУГУИД КАК СотрудникОУГУИД,
	|	ВТ01.Входящий КАК Входящий,
	|	ВТ01.Количество1 КАК Количество1,
	|	ВТ01.Количество2 КАК Количество2,
	|	ВТ01.Количество3 КАК Количество3,
	|	ВТ01.Количество4 КАК Количество4,
	|	ВТ01.Количество5 КАК Количество5,
	|	ВТ01.Количество6 КАК Количество6,
	|	ВТ01.Количество7 КАК Количество7,
	|	ВТ01.Количество8 КАК Количество8,
	|	ВТ01.Количество9 КАК Количество9,
	|	ВТ01.КоличествоИтогоПоСтатусам КАК КоличествоИтогоПоСтатусам,
	|	ВТ01.КоличествоОбщееБезПочты КАК КоличествоОбщееБезПочты,
	|	ВТ01.КоличествоОбщееБезПочты КАК КоличествоОбщее,
	|	ВТ01.Количество2 + ВТ01.Количество3 + ВТ01.Количество8 КАК КоличествоЦелевыхБезПочты,
	|	ВТ01.Количество2 + ВТ01.Количество3 + ВТ01.Количество8 КАК КоличествоЦелевых,
	|	ВТ01.Количество2 + ВТ01.Количество3 + ВТ01.Количество8 КАК ОбщийЦелевой,
	|	ВТ01.Принят КАК Принят,
	|	ЕСТЬNULL(СотрОУ.Ссылка, ЗНАЧЕНИЕ(Справочник.ОУ_Сотрудники.ПустаяСсылка)) КАК Сотрудник,
	|	ЗНАЧЕНИЕ(Справочник.ТочкиЦелевые.ПустаяСсылка) КАК ТочкаЦелевая,
	|	ВТ01.Направление КАК Направление
	|ПОМЕСТИТЬ ВТ03_ЦелевыеОУ
	|ИЗ
	|	ВТ01_ЦелевыеОУ КАК ВТ01
	|		ЛЕВОЕ СОЕДИНЕНИЕ Справочник.ОУ_Сотрудники КАК СотрОУ
	|		ПО ВТ01.СотрудникОУГУИД = СотрОУ.ГУИД
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ЕСТЬNULL(ВТ00.ДатаЗвонка, ВТ03.ДатаЗвонка) КАК ДатаЗвонка,
	|	ЕСТЬNULL(ВТ00.Сигнатура, ВТ03.Сигнатура) КАК Сигнатура,
	|	ЕСТЬNULL(ВТ00.ЦелеваяТочка, ВТ03.ТочкаЦелевая) КАК ТочкаЦелевая,
	|	ВЫБОР
	|		КОГДА ВТ00.Сотрудник ЕСТЬ NULL
	|			ТОГДА ВТ03.Сотрудник
	|		КОГДА ВТ00.Сотрудник = ЗНАЧЕНИЕ(Справочник.ОУ_Сотрудники.ПустаяСсылка)
	|			ТОГДА ВТ03.Сотрудник
	|		ИНАЧЕ ВТ00.Сотрудник
	|	КОНЕЦ КАК Сотрудник,
	|	ВЫБОР
	|		КОГДА НЕ ВТ00.Сигнатура ЕСТЬ NULL
	|				И ЕСТЬNULL(ВТ00.Принят, ЛОЖЬ) = ИСТИНА
	|				И ВТ03.Сигнатура ЕСТЬ NULL
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК КоличествоА,
	|	ВЫБОР
	|		КОГДА НЕ ВТ03.Сигнатура ЕСТЬ NULL
	|				И ВТ00.Сигнатура ЕСТЬ NULL
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК КоличествоБ,
	|	ВЫБОР
	|		КОГДА НЕ ВТ00.Сигнатура ЕСТЬ NULL
	|				И ЕСТЬNULL(ВТ00.Принят, ЛОЖЬ) = ЛОЖЬ
	|				И ВТ03.Сигнатура ЕСТЬ NULL
	|			ТОГДА 1
	|		ИНАЧЕ 0
	|	КОНЕЦ КАК КоличествоГ,
	|	ЕСТЬNULL(ВТ03.Количество1, 0) КАК Количество1,
	|	ЕСТЬNULL(ВТ03.Количество2, 0) КАК Количество2,
	|	ЕСТЬNULL(ВТ03.Количество3, 0) КАК Количество3,
	|	ЕСТЬNULL(ВТ03.Количество4, 0) КАК Количество4,
	|	ЕСТЬNULL(ВТ03.Количество5, 0) КАК Количество5,
	|	ЕСТЬNULL(ВТ03.Количество6, 0) КАК Количество6,
	|	ЕСТЬNULL(ВТ03.Количество7, 0) КАК Количество7,
	|	ЕСТЬNULL(ВТ03.Количество8, 0) КАК Количество8,
	|	ЕСТЬNULL(ВТ03.Количество9, 0) КАК Количество9,
	|	ЕСТЬNULL(ВТ03.КоличествоИтогоПоСтатусам, 0) КАК КоличествоИтогоПоСтатусам,
	|	ЕСТЬNULL(ВТ03.КоличествоОбщееБезПочты, 0) КАК КоличествоОбщееБезПочты,
	|	ЕСТЬNULL(ВТ03.КоличествоОбщееБезПочты, 0) КАК КоличествоОбщее,
	|	ЕСТЬNULL(ВТ03.КоличествоЦелевыхБезПочты, 0) КАК КоличествоЦелевыхБезПочты,
	|	ЕСТЬNULL(ВТ03.КоличествоЦелевыхБезПочты, 0) КАК КоличествоЦелевых,
	|	ЕСТЬNULL(ВТ03.КоличествоЦелевыхБезПочты, 0) КАК ОбщийЦелевой,
	|	ЕСТЬNULL(ВТ00.Принят, ВТ03.Принят) КАК Принят,
	|	ЕСТЬNULL(ВТ03.Направление, ВТ00.Направление) КАК Направление
	|ПОМЕСТИТЬ ВТ05_Звонки
	|ИЗ
	|	ВТ00_ЦелевыеАгрегатора КАК ВТ00
	|		ПОЛНОЕ СОЕДИНЕНИЕ ВТ03_ЦелевыеОУ КАК ВТ03
	|		ПО ВТ00.Сигнатура = ВТ03.Сигнатура
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	НАЧАЛОПЕРИОДА(ВТ05.ДатаЗвонка, ДЕНЬ) КАК ДатаЗвонка,
	|	ВТ05.Сигнатура КАК Сигнатура,
	|	ВТ05.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ05.Сотрудник КАК Сотрудник,
	|	ВТ05.КоличествоА КАК КоличествоА,
	|	ВТ05.КоличествоБ КАК КоличествоБ,
	|	ВТ05.КоличествоГ КАК КоличествоГ,
	|	ВТ05.Количество1 КАК Количество1,
	|	ВТ05.Количество2 КАК Количество2,
	|	ВТ05.Количество3 КАК Количество3,
	|	ВТ05.Количество4 КАК Количество4,
	|	ВТ05.Количество5 КАК Количество5,
	|	ВТ05.Количество6 КАК Количество6,
	|	ВТ05.Количество7 КАК Количество7,
	|	ВТ05.Количество8 КАК Количество8,
	|	ВТ05.Количество9 КАК Количество9,
	|	ВТ05.КоличествоИтогоПоСтатусам КАК КоличествоИтогоПоСтатусам,
	|	ВТ05.КоличествоОбщееБезПочты КАК КоличествоОбщееБезПочты,
	|	ВТ05.КоличествоОбщее КАК КоличествоОбщее,
	|	ВТ05.КоличествоЦелевыхБезПочты КАК КоличествоЦелевыхБезПочты,
	|	ВТ05.КоличествоЦелевых КАК КоличествоЦелевых,
	|	ВТ05.ОбщийЦелевой КАК ОбщийЦелевой,
	|	0 КАК ОбщийЦелевойПрогноз,
	|	ВТ05.ТочкаЦелевая.Регион КАК РегионСтрокой,
	|	ВТ05.Направление КАК НазваниеНаправления,
	|	0 КАК ПорядокНаправлений,
	|	Звонки.ЭтоВходящий КАК ЭтоВходящий,
	|	Звонки.АбонентВнешний КАК АбонентВнешний,
	|	Звонки.Регион КАК РегионАбонента,
	|	Звонки.Инициатор.Код КАК Канал,
	|	ЕСТЬNULL(ИнтернетЗаявки.Сигнатура, ""<без интернет-заявки>"") КАК ИнтернетЗаявка,
	|	ЕСТЬNULL(ИнтернетЗаявки.Инициатор, ""<без интернет-заявки и сайта>"") КАК ИнициаторИнтернетЗаявки,
	|	ВЫБОР
	|		КОГДА ИнтернетЗаявки.Сигнатура ЕСТЬ NULL
	|			ТОГДА Звонки.Инициатор.Код
	|		ИНАЧЕ ИнтернетЗаявки.Инициатор
	|	КОНЕЦ КАК КаналИлиСайт,
	|	ВЫБОР
	|		КОГДА ИнтернетЗаявки.Сигнатура ЕСТЬ NULL
	|			ТОГДА (ВЫРАЗИТЬ(Звонки.Инициатор.Код КАК СТРОКА(11))) + "" "" + (ВЫРАЗИТЬ(Звонки.Инициатор.Назначение КАК СТРОКА(80)))
	|		ИНАЧЕ ИнтернетЗаявки.Инициатор
	|	КОНЕЦ КАК КаналИлиСайтПредставление
	|ПОМЕСТИТЬ ВТ06
	|ИЗ
	|	ВТ05_Звонки КАК ВТ05
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.Звонки КАК Звонки
	|		ПО ВТ05.Сигнатура = Звонки.Сигнатура
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиСтатОбщая КАК Стат
	|		ПО (Звонки.Сигнатура = Стат.Сигнатура)
	|		ЛЕВОЕ СОЕДИНЕНИЕ (ВЫБРАТЬ
	|			Т.Сигнатура КАК Сигнатура,
	|			""iq_"" + Т.Сигнатура КАК Сигнатура2,
	|			Т.Инициатор КАК Инициатор
	|		ИЗ
	|			РегистрСведений.ИнтернетЗаявки КАК Т
	|		ГДЕ
	|			Т.Дата МЕЖДУ ДОБАВИТЬКДАТЕ(&ДатаНачала, ДЕНЬ, -10) И &ДатаОкончания) КАК ИнтернетЗаявки
	|		ПО (Стат.Основание = ИнтернетЗаявки.Сигнатура2)
	|ГДЕ
	|	ВТ05.ТочкаЦелевая.Родитель В ИЕРАРХИИ(&ГруппаЦелевыхТочек)
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	Т.Супергруппа КАК Супергруппа,
	|	Т.Группа КАК Группа,
	|	Т.Сайт КАК Корень
	|ПОМЕСТИТЬ ВТ07_ИерархияМаркетинга
	|ИЗ
	|	&ИерархияМаркетинга КАК Т
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ06.ДатаЗвонка КАК ДатаЗвонка,
	|	ВТ06.Сигнатура КАК Сигнатура,
	|	ВТ06.ТочкаЦелевая КАК ТочкаЦелевая,
	|	ВТ06.Сотрудник КАК Сотрудник,
	|	ВТ06.КоличествоА КАК КоличествоА,
	|	ВТ06.КоличествоБ КАК КоличествоБ,
	|	ВТ06.КоличествоГ КАК КоличествоГ,
	|	ВТ06.Количество1 КАК Количество1,
	|	ВТ06.Количество2 КАК Количество2,
	|	ВТ06.Количество3 КАК Количество3,
	|	ВТ06.Количество4 КАК Количество4,
	|	ВТ06.Количество5 КАК Количество5,
	|	ВТ06.Количество6 КАК Количество6,
	|	ВТ06.Количество7 КАК Количество7,
	|	ВТ06.Количество8 КАК Количество8,
	|	ВТ06.Количество9 КАК Количество9,
	|	ВТ06.КоличествоИтогоПоСтатусам КАК КоличествоИтогоПоСтатусам,
	|	ВТ06.КоличествоОбщееБезПочты КАК КоличествоОбщееБезПочты,
	|	ВТ06.КоличествоОбщее КАК КоличествоОбщее,
	|	ВТ06.КоличествоЦелевыхБезПочты КАК КоличествоЦелевыхБезПочты,
	|	ВТ06.КоличествоЦелевых КАК КоличествоЦелевых,
	|	ВТ06.ОбщийЦелевой КАК ОбщийЦелевой,
	|	ВТ06.ОбщийЦелевойПрогноз КАК ОбщийЦелевойПрогноз,
	|	ВТ06.РегионСтрокой КАК РегионСтрокой,
	|	ВТ06.НазваниеНаправления КАК НазваниеНаправления,
	|	ВТ06.ПорядокНаправлений КАК ПорядокНаправлений,
	|	ВТ06.АбонентВнешний КАК АбонентВнешний,
	|	ВТ06.Канал КАК Канал,
	|	ВТ06.ИнтернетЗаявка КАК ИнтернетЗаявка,
	|	ВТ06.ИнициаторИнтернетЗаявки КАК ИнициаторИнтернетЗаявки,
	|	ВТ06.КаналИлиСайт КАК КаналИлиСайт,
	|	ВТ06.КаналИлиСайтПредставление КАК КаналИлиСайтПредставление,
	|	ЕСТЬNULL(ВТ07.Группа, ""<нет группы нижнего уровня в иерархии>"") КАК ИерархияГруппаНижняя,
	|	ЕСТЬNULL(ВТ07.Супергруппа, ""<нет группы верхнего уровня в иерархии>"") КАК ИерархияГруппаВерхняя,
	|	ЕСТЬNULL(ВТ07.Супергруппа, ""яяяяяяя"") КАК ИерархияГруппаВерхняяСортировка
	|ИЗ
	|	ВТ06 КАК ВТ06
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ07_ИерархияМаркетинга КАК ВТ07
	|		ПО ВТ06.КаналИлиСайт = ВТ07.Корень
	|ГДЕ
	|	ВЫБОР
	|			КОГДА ВТ06.ЭтоВходящий
	|				ТОГДА ИСТИНА
	|			ИНАЧЕ ВТ06.ИнтернетЗаявка <> ""<без интернет-заявки> ""
	|		КОНЕЦ";
	
 	Запрос.УстановитьПараметр("ДатаНачала", 				ДатаНачала);
 	Запрос.УстановитьПараметр("ДатаОкончания", 				ДатаОкончания);
	Запрос.УстановитьПараметр("РеестрЦелевыхТек", 			РеестрЦелевыхТек);
	Запрос.УстановитьПараметр("ТелефоныКонтактЦентра",		ТелефоныКонтактЦентра);
	Запрос.УстановитьПараметр("ГруппаЦелевыхТочек",			ГруппаЦелевыхТочек);
	Запрос.УстановитьПараметр("ИерархияМаркетинга",			ИерархияМаркетинга);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
	
	Возврат РезультатЗапроса;
КонецФункции

Функция СформироватьБазовыеТаблицыЗвонкиВстречиЗадачиЭлПочты(ДатаНачала, ДатаОкончания, ТаблДок) Экспорт
	
	ЗначениеПоУмолчанию = "";
	
	ЭтотОбъект.РеестрЦелевыхТек.Очистить();
	
	ИсточникДанных = Справочники.ИБ_ИсточникиДанных.НайтиПоКоду("000000002");
	Если ИсточникДанных = Неопределено Тогда
		Сообщить("Нет подключения к базе оперативного учета! Данные по встречам будут нулевые");	
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	ПараметрыСоединения = ИсточникДанных.ПараметрыСоединения;
	БИ = ОбщегоНазначения.ПолучитьПодключениеБД(ПараметрыСоединения);	
			
	//Реестр целевых текущего периода из ОУ загрузить
	//-------------------------------------------------
	КодТочкиОформленияУфа = "000000008";
	РеестрЦелевых_Загрузить(БИ, "РеестрЦелевыхТек", ДатаНачала, ДатаОкончания, КодТочкиОформленияУфа, "");
			
	ОбщегоНазначения.РазорватьПодключениеБД(БИ);

КонецФункции

Функция РеестрЦелевых_Загрузить(БИ, ИмяТаблЧасти, ДатаНачала, ДатаОкончания, КодТочкиОформленияКорректировки, ПустаяСтрока) Экспорт
	ЗначениеПоУмолчанию = Ложь;
	
	БИ_Запрос = БИ.NewObject("Запрос");
	БИ_Запрос.Текст = ОбработкаОтчетов.ТексЗапросаРеестрЦелевыхОУ();	
	БИ_Запрос.УстановитьПараметр("ДатаНачала",				ДатаНачала);
	БИ_Запрос.УстановитьПараметр("ДатаОкончания", 			ДатаОкончания);	
	БИ_Запрос.УстановитьПараметр("КодТочкиОформленияУфа", 	КодТочкиОформленияКорректировки);	
	БИ_Запрос.УстановитьПараметр("ПустаяСтрока",		 	ПустаяСтрока);
	
	БИ_РезультатЗапроса = БИ_Запрос.Выполнить();	
	БИ_Выборка = БИ_Запрос.Выполнить().Выбрать();
	
	Пока БИ_Выборка.Следующий() Цикл
		Новая = ЭтотОбъект[ИмяТаблЧасти].Добавить();
		ЗаполнитьЗначенияСвойств(Новая, БИ_Выборка, "ДатаЗвонка, Сигнатура, НомерВнутреннегоТелефона, Состояние, Статус, ОснованиеДля, Количество1, Количество2, Количество3, Количество4, Количество5, Количество6, Количество7, Количество8, КоличествоИтогоПоСтатусам, КоличествоОбщееБезПочты, КоличествоЦелевыхБезПочты, Входящий, Направление");

		Новая.СотрудникОУГУИД				= БИ.XMLСтрока(БИ_Выборка.СотрудникСсылка);	
		Новая.СотрудникНаименование			= БИ_Выборка.СотрудникПредставление;	
		Новая.ТочкаОформленияОУГУИД			= БИ.XMLСтрока(БИ_Выборка.ТочкаОформленияСсылка);
		Новая.ТочкаОформленияНаименование	= БИ_Выборка.ТочкаОформленияПредставление;
		Новая.НавСсылка                     = БИ.ПолучитьНавигационнуюСсылку(БИ_Выборка.Ссылка);
	КонецЦикла;
	
	Возврат  Истина;

КонецФункции
