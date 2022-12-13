﻿
&НаКлиенте
Процедура ОбработкаКоманды(ПараметрКоманды, ПараметрыВыполненияКоманды)
		
	ЗадачаСсылка = ПараметрКоманды;
	
	Доступно = ТипЗнч(ЗадачаСсылка) = Тип("ЗадачаСсылка.ЗадачаОбратнаяСвязь");
	Доступно = Доступно И ЗначениеЗаполнено(ЗадачаСсылка);
	Если Не Доступно Тогда
		Возврат
	КонецЕсли;
	
	Выполнено = ОбработкаКомандыНаСервере(ЗадачаСсылка);
	Если Не Выполнено Тогда
		Сообщ = Новый СообщениеПользователю();
		Сообщ.Текст = "Ошибка записи задачи "+ ЗадачаСсылка;
		Сообщ.Сообщить();
	//// Для отладки		
	////-------------
	//Иначе
	//	Сообщ = Новый СообщениеПользователю();
	//	Сообщ.Текст = "Записана задача "+ЗадачаСсылка;
	//	Сообщ.Сообщить();
	КонецЕсли;
КонецПроцедуры

&НаСервере
Функция ОбработкаКомандыНаСервере(ЗадачаСсылка, ТекПользователь)
	
	ЗначениеПоУмолчанию = Ложь;
	
	Доступно = СтрНайти(ЗадачаСсылка.Наименование, "Обработать")>0;
	Если Не Доступно Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;

	ЗадачаОб = ЗадачаСсылка.ПолучитьОбъект();
	Попытка
		ЗадачаОб.ДатаВыполнения  = ТекущаяДата();
		ЗадачаОб.ИсполнительФакт = ПараметрыСеанса.ТекущийПользователь;
		ЗадачаОб.Выполнить();
	Исключение
		Данные = ЗадачаСсылка;
		Комментарий = ОписаниеОшибки();
		ОбслуживаниеСервер.ЗарегистрироватьСобытие("Ошибка записи задача", УровеньЖурналаРегистрации.Ошибка, Данные, Комментарий);
		Возврат ЗначениеПоУмолчанию;
	КонецПопытки;
	
	Возврат Истина;
		
КонецФункции
