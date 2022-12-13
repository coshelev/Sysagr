﻿&НаКлиенте
Процедура ПриОткрытии(Отказ)
	ПодстрокаПоискаПриИзменении();
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ПодстрокаПоискаПриИзменении(Элемент = Неопределено)

// Удалим существующий отбор
//-------------------------------------------------------------------------------------------------
	Для Каждого ТекСтрока Из ЭтаФорма.Список.Отбор.Элементы Цикл
		Если (ТекСтрока.Представление = "ОтборПоПодстрокеПоиска") Тогда
			ЭтаФорма.Список.Отбор.Элементы.Удалить(ТекСтрока);
		КонецЕсли;
	КонецЦикла;

// Если подстрока поиска не заполнена, то завершим процедуру
//-------------------------------------------------------------------------------------------------
	Если (НЕ ЗначениеЗаполнено(ЭтаФорма.ПодстрокаПоиска)) Тогда
		Элементы.Список.Отображение = ОтображениеТаблицы.ИерархическийСписок;
		ЭтаФорма.ТекущийЭлемент = Элементы.ПодстрокаПоиска;

// Если подстрока поиска заполнена, то сформируем условие фильтрации
// Поиск может производиться по одному или нескольким словам
//-------------------------------------------------------------------------------------------------
	Иначе
		МассивСлов = Конвертация.СтрокаРазделить(СокрЛП(ЭтаФорма.ПодстрокаПоиска)," ");
		ГруппаОтбора = ЭтаФорма.Список.Отбор.Элементы.Добавить(Тип("ГруппаЭлементовОтбораКомпоновкиДанных"));
		ГруппаОтбора.РежимОтображения = РежимОтображенияЭлементаНастройкиКомпоновкиДанных.Недоступный;
		ГруппаОтбора.ТипГруппы = ТипГруппыЭлементовОтбораКомпоновкиДанных.ГруппаИ;
		ГруппаОтбора.Представление = "ОтборПоПодстрокеПоиска";
		ГруппаОтбора.Использование = Истина;

		Для Каждого ТекСлово Из МассивСлов Цикл
			ВнутрГруппаОтбора = ГруппаОтбора.Элементы.Добавить(Тип("ГруппаЭлементовОтбораКомпоновкиДанных"));
			ВнутрГруппаОтбора.РежимОтображения = РежимОтображенияЭлементаНастройкиКомпоновкиДанных.Недоступный;
			ВнутрГруппаОтбора.ТипГруппы = ТипГруппыЭлементовОтбораКомпоновкиДанных.ГруппаИЛИ;
			ВнутрГруппаОтбора.Использование = Истина;

			ЭлементОтбора = ВнутрГруппаОтбора.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));
			ЭлементОтбора.ЛевоеЗначение		= Новый ПолеКомпоновкиДанных("НаименованиеПолное");
			ЭлементОтбора.ВидСравнения		= ВидСравненияКомпоновкиДанных.Содержит;
			ЭлементОтбора.ПравоеЗначение	= СокрЛП(ТекСлово);
			ЭлементОтбора.Использование		= Истина;

			ЭлементОтбора = ВнутрГруппаОтбора.Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));
			ЭлементОтбора.ЛевоеЗначение		= Новый ПолеКомпоновкиДанных("Телефоны");
			ЭлементОтбора.ВидСравнения		= ВидСравненияКомпоновкиДанных.Содержит;
			ЭлементОтбора.ПравоеЗначение	= СокрЛП(ТекСлово);
			ЭлементОтбора.Использование		= Истина;
		КонецЦикла;

		Элементы.Список.Отображение = ОтображениеТаблицы.Список;
		ЭтаФорма.ТекущийЭлемент = Элементы.Список;
	КонецЕсли;
КонецПроцедуры

&НаКлиенте
Процедура СписокВыбор(Элемент,ВыбраннаяСтрока,Поле,СтандартнаяОбработка)

// Если пользователь выбрал строку и эта строка является группой, то необходимо проверить
// используется ли фильтр для поиска по Списку (заполненность реквизита "ПодстрокаПоиска")
// Если реквизит заполнен (т.е. фильтр существует), то для правильного входа в группу и отображения
// элементов группы - очистим фильтр и переведем режим отображения списка в "ИерархическийСписок"
//-------------------------------------------------------------------------------------------------
	Если (Элемент.ТекущиеДанные.ЭтоГруппа = Истина) Тогда
		ЭтаФорма.ПодстрокаПоиска = Неопределено;
		ПодстрокаПоискаПриИзменении();
	КонецЕсли;
КонецПроцедуры
