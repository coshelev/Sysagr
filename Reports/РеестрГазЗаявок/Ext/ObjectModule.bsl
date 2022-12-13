﻿
Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
		
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	ГАЗЗаявки.Сигнатура КАК Сигнатура,
	|	ГАЗЗаявки.Начало КАК Начало,
	|	ГАЗЗаявки.Окончание КАК Окончание,
	|	ГАЗЗаявки.АбонентВнешний КАК АбонентВнешний,
	|	ГАЗЗаявки.Почта КАК Почта,
	|	ГАЗЗаявки.Ид КАК Ид,
	|	ГАЗЗаявки.ТочкаРазмещения КАК Регион,
	|	ГАЗЗаявки.Автор КАК Автор
	|ПОМЕСТИТЬ ВТ01_Заявки
	|ИЗ
	|	РегистрСведений.ГАЗЗаявки КАК ГАЗЗаявки
	|ГДЕ
	|	ГАЗЗаявки.Начало МЕЖДУ &Начало И &Окончание
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ЗадачиКЦ.ПричинаЗакрытия КАК ПричинаЗакрытия,
	|	ЗадачиКЦ.ЗвонокЗакрытия КАК ЗвонокЗакрытия,
	|	ЗадачиКЦ.Сигнатура КАК Сигнатура,
	|	ЗадачиКЦ.ДатаЗакрытия КАК ДатаЗакрытия,
	|	ЗадачиКЦ.Исполнитель КАК Исполнитель
	|ПОМЕСТИТЬ ВТ05_ВсеЗакрытыеКЦЗадачиПоЗакрытымЗаявкам
	|ИЗ
	|	РегистрСведений.ЗадачиГАЗЗаявки КАК ЗадачиКЦ
	|ГДЕ
	|	ЗадачиКЦ.АдресацияРоль = ЗНАЧЕНИЕ(Справочник.Роли.ОператорКонтактЦентра)
	|	И ЗадачиКЦ.ДатаЗакрытия <> ДАТАВРЕМЯ(1, 1, 1)
	|	И ЗадачиКЦ.Сигнатура В
	|			(ВЫБРАТЬ
	|				ВТ01.Сигнатура
	|			ИЗ
	|				ВТ01_Заявки КАК ВТ01
	|			ГДЕ
	|				ВТ01.Окончание <> ДАТАВРЕМЯ(1, 1, 1))
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ01.Сигнатура КАК Сигнатура,
	|	ВТ05.ДатаЗакрытия КАК ДатаЗакрытия,
	|	РАЗНОСТЬДАТ(ВТ05.ДатаЗакрытия, ВТ01.Окончание, СЕКУНДА) КАК РазностьДат
	|ПОМЕСТИТЬ ВТ10_ВсеЗакрытыеКЦЗадачиПоЗакрытымЗаявкам
	|ИЗ
	|	ВТ01_Заявки КАК ВТ01
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ05_ВсеЗакрытыеКЦЗадачиПоЗакрытымЗаявкам КАК ВТ05
	|		ПО ВТ01.Сигнатура = ВТ05.Сигнатура
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ10.Сигнатура КАК Сигнатура,
	|	МИНИМУМ(ВТ10.РазностьДат) КАК РазностьДат
	|ПОМЕСТИТЬ ВТ15_НаименьшаяРазностьДатаЗакрытияЗадачиИЗаявки
	|ИЗ
	|	ВТ10_ВсеЗакрытыеКЦЗадачиПоЗакрытымЗаявкам КАК ВТ10
	|
	|СГРУППИРОВАТЬ ПО
	|	ВТ10.Сигнатура
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ10.Сигнатура КАК Сигнатура,
	|	ВТ10.ДатаЗакрытия КАК ДатаЗакрытия,
	|	ВЫБОР
	|		КОГДА ВТ05.ЗвонокЗакрытия <> """"
	|			ТОГДА ЕСТЬNULL(Звонки.ИнициаторИсходящего, ЗНАЧЕНИЕ(Справочник.Пользователи.ПустаяСсылка))
	|		ИНАЧЕ ВТ05.Исполнитель
	|	КОНЕЦ КАК Исполнитель,
	|	ВЫБОР
	|		КОГДА ВТ05.ЗвонокЗакрытия <> """"
	|			ТОГДА ВТ05.ЗвонокЗакрытия
	|		ИНАЧЕ ВТ05.ПричинаЗакрытия
	|	КОНЕЦ КАК ПричинаЗакрытия
	|ПОМЕСТИТЬ ВТ20_ПоследниеЗакрытыеЗадачиКЦПоЗакрытымЗаявкам
	|ИЗ
	|	ВТ10_ВсеЗакрытыеКЦЗадачиПоЗакрытымЗаявкам КАК ВТ10
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ15_НаименьшаяРазностьДатаЗакрытияЗадачиИЗаявки КАК ВТ15
	|		ПО ВТ10.РазностьДат = ВТ15.РазностьДат
	|		ВНУТРЕННЕЕ СОЕДИНЕНИЕ ВТ05_ВсеЗакрытыеКЦЗадачиПоЗакрытымЗаявкам КАК ВТ05
	|		ПО (ВТ05.Сигнатура = ВТ10.Сигнатура)
	|			И (ВТ05.ДатаЗакрытия = ВТ10.ДатаЗакрытия)
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗвонкиСтатОбщая КАК Звонки
	|		ПО (ВТ05.ЗвонокЗакрытия <> """")
	|			И (ВТ05.ЗвонокЗакрытия = Звонки.Сигнатура)
	|;
	|
	|////////////////////////////////////////////////////////////////////////////////
	|ВЫБРАТЬ
	|	ВТ01.Сигнатура КАК Сигнатура,
	|	ВТ01.Ид КАК Ид,
	|	ВТ01.Регион КАК Регион,
	|	ВТ01.Начало КАК Начало,
	|	ВТ01.Окончание КАК Окончание,
	|	ВТ01.Автор КАК Постановщик,
	|	ЕСТЬNULL(ВТ20.Исполнитель, ЗНАЧЕНИЕ(Справочник.Пользователи.ПустаяСсылка)) КАК Исполнитель,
	|	ЕСТЬNULL(ВТ20.ПричинаЗакрытия, """") КАК ПричинаЗакрытия,
	|	ЕСТЬNULL(ЗадачиПроверки.Исполнитель, ЗНАЧЕНИЕ(Справочник.Пользователи.ПустаяСсылка)) КАК Проверяющий
	|ИЗ
	|	ВТ01_Заявки КАК ВТ01
	|		ЛЕВОЕ СОЕДИНЕНИЕ ВТ20_ПоследниеЗакрытыеЗадачиКЦПоЗакрытымЗаявкам КАК ВТ20
	|		ПО ВТ01.Сигнатура = ВТ20.Сигнатура
	|		ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЗадачиГАЗЗаявки КАК ЗадачиПроверки
	|		ПО (ЗадачиПроверки.АдресацияРоль <> ЗНАЧЕНИЕ(Справочник.Роли.ОператорКонтактЦентра))
	|			И (ЗадачиПроверки.ДатаЗакрытия <> ДАТАВРЕМЯ(1, 1, 1))
	|			И (ЕСТЬNULL(ЗадачиПроверки.ДатаПостановки, ДАТАВРЕМЯ(1, 1, 1)) = ЕСТЬNULL(ВТ20.ДатаЗакрытия, ДАТАВРЕМЯ(1, 1, 1)))";
	
	Запрос.УстановитьПараметр("Начало", 	Период.ДатаНачала);
	Запрос.УстановитьПараметр("Окончание",	Период.ДатаОкончания);
	
	РезультатЗапроса = Запрос.Выполнить();
	ТЗ = РезультатЗапроса.Выгрузить();
	
	ВнешниеНаборыДанных = Новый Структура();
	ВнешниеНаборыДанных.Вставить("ТЗ", ТЗ);
	
	СКД = ПолучитьМакет("ОсновнаяСКД");	
	Настройки = ЭтотОбъект.КомпоновщикНастроек.ПолучитьНастройки();
		
	КомпоновщикМакета = Новый КомпоновщикМакетаКомпоновкиДанных();
	МакетКомпоновки = КомпоновщикМакета.Выполнить(СКД, Настройки, ДанныеРасшифровки);
	ПроцессорКомпоновкиДанных = Новый ПроцессорКомпоновкиДанных();
	ПроцессорКомпоновкиДанных.Инициализировать(МакетКомпоновки, ВнешниеНаборыДанных, ДанныеРасшифровки);
	 
	ПроцессорВывода = Новый ПроцессорВыводаРезультатаКомпоновкиДанныхВТабличныйДокумент();
	ПроцессорВывода.УстановитьДокумент(ДокументРезультат);
	ПроцессорВывода.Вывести(ПроцессорКомпоновкиДанных);


КонецПроцедуры
