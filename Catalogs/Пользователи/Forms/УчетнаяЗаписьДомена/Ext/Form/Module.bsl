﻿&НаКлиенте
Процедура ПриОткрытии(Отказ)

// Сформируем список выбора для реквизита "Домен" (только нелокальные домены)
//-------------------------------------------------------------------------------------------------
	Элементы.Домен.СписокВыбора.Очистить();
	Домены = ПользователиОС();

	Для Каждого ТекСтрока Из Домены Цикл
		Если (ТекСтрока.Локальный = Ложь) Тогда
			Элементы.Домен.СписокВыбора.Добавить(СокрЛП(ТекСтрока.ИмяДомена));
		КонецЕсли;
	КонецЦикла;

// Выполним сортировку списка доменов
// Установим первоначальное значение для реквизита Домен
//-------------------------------------------------------------------------------------------------
	Если (Элементы.Домен.СписокВыбора.Количество() > 0) Тогда
		НовЗначение = Элементы.Домен.СписокВыбора[0].Значение;
		ЭтаФорма.Домен = НовЗначение;
		ДоменПриИзменении(Элементы.Домен);
	КонецЕсли;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ДоменПриИзменении(Элемент)

// Если домен не выбран, то завершим обработку
//-------------------------------------------------------------------------------------------------
	ЭтаФорма.Пользователи.Очистить();

	Если (НЕ ЗначениеЗаполнено(ЭтаФорма.Домен)) Тогда
		Возврат;
	КонецЕсли;

// Сформируем список пользователей домена
//-------------------------------------------------------------------------------------------------
	Домены = ПользователиОС();

	Для Каждого ТекДомен Из Домены Цикл
		Если (ВРег(СокрЛП(ЭтаФорма.Домен)) = ВРег(СокрЛП(ТекДомен.ИмяДомена))) Тогда
			Для Каждого ТекСтрока Из ТекДомен.Пользователи Цикл
				ЭтаФорма.Пользователи.Добавить(СокрЛП(ТекСтрока));
			КонецЦикла;
		КонецЕсли;
	КонецЦикла;
КонецПроцедуры

&НаКлиенте
Процедура ДоменОчистка(Элемент,СтандартнаяОбработка)
	СтандартнаяОбработка = Ложь;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ПользователиВыбор(Элемент,ВыбраннаяСтрока,Поле,СтандартнаяОбработка)
	Выбрать(Неопределено);
КонецПроцедуры

&НаКлиенте
Процедура Выбрать(Команда)

// Если пользователь совершил выбор, то сформируем полное имя пользователя и вернем результат
//-------------------------------------------------------------------------------------------------
	Если (Элементы.Пользователи.ТекущиеДанные <> Неопределено) Тогда
		Ответ = "\\" + ВРег(СокрЛП(ЭтаФорма.Домен)) + "\";
		Ответ = Ответ + СокрЛП(Элементы.Пользователи.ТекущиеДанные.Значение);
		ЭтаФорма.Закрыть(Ответ);
	КонецЕсли;
КонецПроцедуры
