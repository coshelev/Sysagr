﻿
&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	ЭтаФорма.ЗакрыватьПриВыборе= Ложь;
	
	Если Не ЗначениеЗаполнено(Параметры.Вопрос) Тогда
		Возврат;
	КонецЕсли;
	
	Запрос = Новый Запрос();
	Запрос.Текст = 
	"ВЫБРАТЬ
	|	АнкетыВариантыОтветов.Ответ КАК Ответ
	|ИЗ
	|	Справочник.Анкеты.ВариантыОтветов КАК АнкетыВариантыОтветов
	|ГДЕ
	|	АнкетыВариантыОтветов.Ссылка = &Вопрос";
	Запрос.УстановитьПараметр("Вопрос", Параметры.Вопрос);
	РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос, ПараметрыСеанса.ТекущийПользователь.Наименование);
	Если РезультатЗапроса.Пустой() Тогда
		Возврат;
	КонецЕсли;
	Выборка = РезультатЗапроса.Выбрать();
	Пока Выборка.Следующий() Цикл
		СписокОтветов.Добавить(Выборка.Ответ, Выборка.Ответ, Ложь);
	КонецЦикла;
	
	ЭтаФорма.Элементы.Комментарий.Видимость = Ложь;
	Если ЗначениеЗаполнено(Параметры.Комментарий) Тогда
		ЭтаФорма.Элементы.Комментарий.Видимость = Истина;
		ЭтаФорма.Комментарий = Параметры.Комментарий;
	КонецЕсли;
КонецПроцедуры

&НаКлиенте
Процедура Выбрать(Команда)	
	Для Каждого Отв Из СписокОтветов Цикл
		Если Отв.Пометка Тогда
			ВыбранныеЗначения.Добавить(Отв.Значение, Отв.Значение);
		КонецЕсли;
	КонецЦикла;
	
	ЭтаФорма.Закрыть(ЭтаФорма.ВыбранныеЗначения);
КонецПроцедуры

&НаКлиенте
Процедура СписокВыбор(Элемент, ВыбраннаяСтрока, Поле, СтандартнаяОбработка)
	ЭтаФорма.ВыбранныеЗначения.Добавить(ЭтаФорма.Элементы.Список.ТекущиеДанные.Ответ);
КонецПроцедуры

&НаКлиенте
Процедура СписокОтветовВыбор(Элемент, ВыбраннаяСтрока, Поле, СтандартнаяОбработка)
	
	ЭлСписка = ЭтаФорма.СписокОтветов.НайтиПоИдентификатору(ВыбраннаяСтрока);
	ЭлСписка.Пометка = НЕ ЭлСписка.Пометка;
	
КонецПроцедуры
