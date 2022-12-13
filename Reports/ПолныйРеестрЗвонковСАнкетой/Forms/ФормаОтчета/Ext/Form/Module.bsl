﻿
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
	//Если Диалог.Редактировать() Тогда 
	//	Отчет.Период = Диалог.Период; 
	//КонецЕсли;
	
	//ОбновитьОтображение();
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
	рез = РезультатОбработкаРасшифровкиНаСервере(Расшифровка);
	
	Если Не ЗначениеЗаполнено(Рез) Тогда
		Возврат
	КонецЕсли;
	
	Если ТипЗнч(Рез)<>Тип("Строка") Тогда
		Возврат;
	КонецЕсли;
	
	Если СтрНайти(Рез, "#", , 2) =0 Тогда
		Возврат
	КонецЕсли;
	
	Парам = Новый Структура();
	Парам.Вставить("Сигнатура", рез);
	Если Лев(Рез,1) = "0" Тогда
		ИмяОткрываемойФормы = "РегистрСведений.Звонки.Форма.ФормаИсходящего";
	Иначе
		ИмяОткрываемойФормы = "РегистрСведений.Звонки.Форма.ФормаВходящего";
	КонецЕсли;
	ОткрытьФорму(ИмяОткрываемойФормы, Парам, ЭтаФорма,,,,, РежимОткрытияОкнаФормы.БлокироватьОкноВладельца);

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


 
