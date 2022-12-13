﻿&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	
	//Создай список вариантов отчета
	//--------------------------------
	Элементы.ВыбранныйВариантОтчета.СписокВыбора.Добавить("а", 	"Лояльность: детальный");
	//Элементы.ВыбранныйВариантОтчета.СписокВыбора.Добавить("б", 	"Детальный");
	
	//Выбери вариант по умолчанию
	//----------------------------
	Отчет.ВыбранныйВариантОтчета="а";

	Отчет.ТипПериода = 0;
КонецПроцедуры

&НаКлиенте
Процедура ВидимостьНастроек(Команда)
	Элементы.ГруппаСтраницы.Видимость = НЕ Элементы.ГруппаСтраницы.Видимость;
	ОбновитьОтображение();
КонецПроцедуры

&НаКлиенте
Процедура ПриОткрытии(Отказ)
	Отчет.Период.ДатаНачала = НачалоМесяца(ТекущаяДата());
	Отчет.Период.ДатаОкончания = КонецМесяца(Отчет.Период.ДатаНачала);
	
	Элементы.ГруппаСтраницы.Видимость = Ложь;
	
	ОбновитьОтображение();
КонецПроцедуры

&НаКлиенте
Процедура ВыборПериода(Команда)
	Диалог = Новый ДиалогРедактированияСтандартногоПериода(); 
	Диалог.Период = Отчет.Период;
	
	Оп = Новый ОписаниеОповещения("НаЗакрытиеДиалогаПериода", ЭтаФорма);
	Диалог.Показать(Оп);
КонецПроцедуры

&НаКлиенте
Процедура НаЗакрытиеДиалогаПериода(Парам1, Парам2) Экспорт
	Если Парам1 = Неопределено Тогда
		Возврат
	КонецЕсли;
	Отчет.Период = Парам1;
	ОбновитьОтображение();
КонецПроцедуры

&НаКлиенте
Процедура ОбновитьОтображение()
	Элементы.ВыборПериода.Заголовок = " "+Формат(Отчет.Период.ДатаНачала, "ДЛФ=Д")+" - "+Формат(Отчет.Период.ДатаОкончания, "ДЛФ=Д");
	Элементы.ВидимостьНастроек.Пометка = Элементы.ГруппаСтраницы.Видимость;
КонецПроцедуры

&НаКлиенте
Процедура РезультатОбработкаРасшифровки(Элемент, Расшифровка, СтандартнаяОбработка, ДополнительныеПараметры)
	
	СтандартнаяОбработка = Ложь;
	Расш = РезультатОбработкаРасшифровкиНаСервере(Расшифровка);
	
	Если Не ЗначениеЗаполнено(Расш.Поле) Тогда
		Возврат
	КонецЕсли;
	
	//Если пользователь пытается открыть список звонков
	//--------------------------------------------------
	Доступно = Истина;
	Доступно = Доступно И Расш.Поле = "ВычЗвонки";
	Доступно = Доступно И СтрДлина(Расш.Значение)>3;
	Если Доступно Тогда
		ЗвонкиПоАнкетеЛояльности = ЗвонкиПоАнкетеЛояльности(Расш.Значение);
		Если ЗвонкиПоАнкетеЛояльности.Количество()=0 Тогда
			ПоказатьПредупреждение(, "Звонки, не найдены", 5);
		ИначеЕсли ЗвонкиПоАнкетеЛояльности.Количество()=1 Тогда
			Парам = Новый Структура();
			Парам.Вставить("Сигнатура", ЗвонкиПоАнкетеЛояльности[0]);
			ОткрытьФорму("РегистрСведений.Звонки.Форма.ФормаИсходящего", Парам, ЭтаФорма,,,, , РежимОткрытияОкнаФормы.БлокироватьОкноВладельца);
		Иначе	
			Сигнатуры = Новый СписокЗначений();
			Сигнатуры.ЗагрузитьЗначения(ЗвонкиПоАнкетеЛояльности);
			Парам = Новый Структура();
			Парам.Вставить("Сигнатуры", Сигнатуры);
			ОткрытьФорму("РегистрСведений.Звонки.Форма.СписокИсходящих", Парам, ЭтаФорма,,,, , РежимОткрытияОкнаФормы.БлокироватьОкноВладельца);
		КонецЕсли;
		Возврат;	
	КонецЕсли;
	
	Доступно = Истина;
	Доступно = Доступно И Расш.Поле = "ВычАнкетаОбратнойСвязи";
	Доступно = Доступно И СтрДлина(Расш.Значение)>3;
	Если Доступно Тогда
		Парам = Новый Структура("СигнатураЗадачи", Расш.Значение);
		ОткрытьФорму("РегистрСведений.АнкетыОбратнойСвязи.Форма.ФормаСпискаОднойАнкеты", Парам, ЭтаФорма,,,,, РежимОткрытияОкнаФормы.БлокироватьОкноВладельца);
		Возврат;
	КонецЕсли;

КонецПроцедуры

&НаСервере
Функция РезультатОбработкаРасшифровкиНаСервере(Расшифровка) 
	Перем Рез;
	Рез = Новый Структура("Поле, Значение", " "", """);
	
	РасшифровкаОтчета = ПолучитьИзВременногоХранилища(ЭтаФорма.ДанныеРасшифровки);
	ЭлементыРасшифровки = РасшифровкаОтчета.Элементы;
	РасшифровкаЯчейки =  ЭлементыРасшифровки.Получить(Расшифровка);
	ЗначенияПолейРасш = РасшифровкаЯчейки.ПолучитьПоля();
	ЗначениеПоляРасш = ЗначенияПолейРасш.Получить(0);
	
	ЗаполнитьЗначенияСвойств(Рез, ЗначениеПоляРасш);
	Возврат Рез;
КонецФункции

&НаСервере
Функция ЗвонкиПоАнкетеЛояльности(АнкетаЛояльности)
	Перем Рез;
	Рез = Новый Массив();
	
	Доступно = Истина;
	Доступно = Доступно И ТипЗнч(АнкетаЛояльности) = Тип("Строка");
	Доступно = Доступно И СтрНайти(АнкетаЛояльности, "#")>0;
	Если Не Доступно Тогда
		Возврат Рез;
	КонецЕсли;
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	ЗвонкиСтатОбщая.Сигнатура КАК Сигнатура
	|ИЗ
	|	РегистрСведений.ЗвонкиСтатОбщая КАК ЗвонкиСтатОбщая
	|ГДЕ
	|	ЗвонкиСтатОбщая.Основание В (&Основание1, &Основание2)";
	Запрос.УстановитьПараметр("Основание1", "pr_"+АнкетаЛояльности);
	Запрос.УстановитьПараметр("Основание2",	"zn_"+АнкетаЛояльности);
	РезультатЗапроса = Запрос.Выполнить();
	Если РезультатЗапроса.Пустой() Тогда
		Возврат Рез;
	КонецЕсли;
	
	Рез = РезультатЗапроса.Выгрузить().ВыгрузитьКолонку(0);
	Возврат Рез;
КонецФункции



 
