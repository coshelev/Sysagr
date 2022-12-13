﻿&НаСервере
Процедура ПриЗагрузкеВариантаНаСервере(Настройки)
	ТекДата = ТекущаяДата();
	ПредДата = КонецДня(НачалоДня(ТекДата)-1);
	ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.ПараметрыДанных.УстановитьЗначениеПараметра("НачалоПериода",	НачалоМесяца(ТекДата));
	ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.ПараметрыДанных.УстановитьЗначениеПараметра("КонецПериода",	ПредДата);
КонецПроцедуры

&НаКлиенте
Процедура РезультатОбработкаРасшифровки(Элемент, Расшифровка, СтандартнаяОбработка)
	
	СтандартнаяОбработка = Ложь;
	
	СтруктПолей = РезультатОбработкаРасшифровкиНаСервере(Расшифровка);
	
	Доступно = ЗначениеЗаполнено(СтруктПолей.ИмяПараметра);
	Доступно = Доступно И ЗначениеЗаполнено(СтруктПолей.Подразделение);
		
	Если Не Доступно Тогда
		Возврат
	КонецЕсли;
	
	Если ЗначениеЗаполнено(СтруктПолей.Дата) Тогда
		//пользователь расшифровывает один день 
		ДатаНачала		=	НачалоДня(СтруктПолей.Дата);
		ДатаОкончания	=	КонецДня(СтруктПолей.Дата);
	Иначе
		//пользователь расшифровывает данные за весь период отчета
		ЗаданныйПериодВРасшифровке=ПолучиПараметрОтчета("Период");
		
		ДатаНачала		=	ЗаданныйПериодВРасшифровке.ДатаНачала;
		ДатаОкончания	=	ЗаданныйПериодВРасшифровке.ДатаОкончания;
	КонецЕсли;
	//МинВремяОжиданияВОчереди 	= ПолучиПараметрОтчета("МинВремяОжиданияВОчереди");
	//НормаВремениОжиданияКЦ		= ПолучиПараметрОтчета("НормаВремениОжиданияКЦ");	
	СформироватьОтчет_КолвоНепринятыхЗвонковРасшифровка(ДатаНачала, ДатаОкончания);
	
КонецПроцедуры

&НаСервере
Функция РезультатОбработкаРасшифровкиНаСервере(Расшифровка)
	
	СтруктураПолей = Новый Структура();
	СтруктураПолей.Вставить("Дата");
	СтруктураПолей.Вставить("ИмяПараметра");
	СтруктураПолей.Вставить("Подразделение");
	
	ЗНАЧЕНИЕ_ПО_УМОЛЧАНИЮ = СтруктураПолей;
	
	//Получи расшифровку всего отчета	
	ДанныеРасш = ПолучитьИзВременногоХранилища(ЭтаФорма.АдресРасшифровкиВоВременномХранилище);  
		
	//Получи  элемент расшифровки, т.е. расшифровку ячейки
	Элемент = ДанныеРасш.Элементы[Расшифровка]; 	
	ЗаполнитьСтруктуруПолей(СтруктураПолей, Элемент);
	
	Возврат СтруктураПолей;
КонецФункции

&НаСервере
Процедура ЗаполнитьСтруктуруПолей(СтруктураПолей, Элемент);
    Если ТипЗнч(Элемент) <>    Тип("ЭлементРасшифровкиКомпоновкиДанныхГруппировка") Тогда
        Для Каждого ТекущееПоле Из Элемент.ПолучитьПоля() Цикл
            //Если Не СтруктураПолей.Свойство(ТекущееПоле.Поле) Тогда
				//Удали из имени пользовательских полей символ "."
				ИмяТекущегоПоля = СтрЗаменить(ТекущееПоле.Поле, ".", "");
                СтруктураПолей.Вставить(ИмяТекущегоПоля, ТекущееПоле.Значение);	
            //КонецЕсли;
        КонецЦикла;
    КонецЕсли;
   //проверим родителей
 
    РодителиПоляГруппировки = Элемент.ПолучитьРодителей();
    Для Каждого ТекущийРодительГруппировка Из РодителиПоляГруппировки Цикл
        ЗаполнитьСтруктуруПолей(СтруктураПолей, ТекущийРодительГруппировка);
    КонецЦикла;
КонецПроцедуры

&НаСервере
Функция ПолучиПараметрОтчета(ИмяПараметра)
	//Получи расшифровку всего отчета	
	ДанныеРасш = ПолучитьИзВременногоХранилища(ЭтаФорма.АдресРасшифровкиВоВременномХранилище);  

	//Период отчета из настроек отчета
	ЗаданныйПериодВРасшифровке = ДанныеРасш.Настройки.ПараметрыДанных.Элементы.Найти(ИмяПараметра).Значение; 
	
	Возврат ЗаданныйПериодВРасшифровке;
КонецФункции

&НаКлиенте
Процедура СформироватьОтчет_КолвоНепринятыхЗвонковРасшифровка(ДатаНачала, ДатаОкончания)
	
	
	НастройкиОтчетаРасш = ПолучиНастройкиСКД();
   Для Каждого Эл Из ЭтаФорма.Отчет.КомпоновщикНастроек.Настройки.ПараметрыДанных.Элементы Цикл
		НовыйЭл = НастройкиОтчетаРасш.ПараметрыДанных.Элементы.Добавить();
		ЗаполнитьЗначенияСвойств(НовыйЭл, Эл);
	КонецЦикла;
   
	НастройкиОтчетаРасш.ПараметрыДанных.УстановитьЗначениеПараметра("НачалоПериода", ДатаНачала);
	НастройкиОтчетаРасш.ПараметрыДанных.УстановитьЗначениеПараметра("КонецПериода", ДатаОкончания);
		
	ТаблДок = СформироватьОтчет_КолвоНепринятыхЗвонковРасшифровка_НаСервере(НастройкиОтчетаРасш);
	ТаблДок.Показать("Расшифровка: количество непринятых звонков");
КонецПроцедуры

&НаСервере
Функция ПолучиНастройкиСКД()
	СКД = Отчеты.KPI_КЦ_Упрощенный.ПолучитьМакет("КолВоНепринятыхЗвонковРасшифровка");
	Возврат СКД.НастройкиПоУмолчанию;	
КонецФункции

&НаСервере
Функция СформироватьОтчет_КолвоНепринятыхЗвонковРасшифровка_НаСервере(НастройкиСКД)
	
	СКД = Отчеты.KPI_КЦ_Упрощенный.ПолучитьМакет("КолВоНепринятыхЗвонковРасшифровка");
	
	КомпоновщикМакета = Новый КомпоновщикМакетаКомпоновкиДанных();
	//МакетКомпоновки = КомпоновщикМакета.Выполнить(СКД, НастройкиСКД,, , Тип("ГенераторМакетаКомпоновкиДанных"));
	МакетКомпоновки = КомпоновщикМакета.Выполнить(СКД, НастройкиСКД,, , Тип("ГенераторМакетаКомпоновкиДанныхДляКоллекцииЗначений"));

	
	ПроцессорКомпоновки =  Новый ПроцессорКомпоновкиДанных();
	ПроцессорКомпоновки.Инициализировать(МакетКомпоновки,,,);

	//ПроцессорВывода = Новый ПроцессорВыводаРезультатаКомпоновкиДанныхВТабличныйДокумент();
	ПроцессорВывода = Новый ПроцессорВыводаРезультатаКомпоновкиДанныхВКоллекциюЗначений();

	ТаблДок = ПроцессорВывода.Вывести(ПроцессорКомпоновки);
	Возврат ТаблДок;
КонецФункции




